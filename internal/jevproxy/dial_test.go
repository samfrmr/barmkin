package jevproxy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestDialPinnedDetectsImpostor is the uid-pin check the Firstmate spec
// asks for: a caller that pins the proxy's required uid (0, root, in
// production) must refuse a listener on the same socket path served by
// any other uid, including one running as the caller's own uid - exactly
// the same-uid impostor scenario the scout report's TestLabLoopbackListenerUID
// covers for a TCP listener. A test cannot bind a real uid-0 socket
// without being root, so this proves the detection the other way around:
// pinning a uid nobody here is refuses a listener that is, in fact, the
// test's own real process.
func TestDialPinnedDetectsImpostor(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "impostor.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	notMe := uint32(os.Getuid()) + 999999
	if _, err := DialPinned(t.Context(), socket, notMe); err == nil {
		t.Fatal("DialPinned accepted a listener that is not the pinned uid")
	}
}

// TestDialPinnedAcceptsThePinnedUID proves the pin lets through the
// uid it is actually configured to require: the dial succeeds when the
// listener is, in fact, served by that uid.
func TestDialPinnedAcceptsThePinnedUID(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "real.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	conn, err := DialPinned(t.Context(), socket, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("DialPinned refused the socket's real uid: %v", err)
	}
	conn.Close()
}

func TestDialPinnedRefusesAMissingSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "absent.sock")
	if _, err := DialPinned(t.Context(), socket, 0); err == nil {
		t.Fatal("DialPinned connected to a socket that does not exist")
	}
}
