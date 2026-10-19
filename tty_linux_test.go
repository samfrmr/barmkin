package main

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"unsafe"
)

// isTerminal tells a terminal from a pipe and a file.
func TestIsTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(r) {
		t.Error("a pipe is a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("a file is a terminal")
	}
	leader, pty, err := openPTY()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer leader.Close()
	defer pty.Close()
	if !isTerminal(pty) {
		t.Error("a pseudo-terminal is not a terminal")
	}
}

// openPTY opens a new pseudo-terminal: its leader and its follower.
func openPTY() (leader, follower *os.File, err error) {
	leader, err = os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, leader.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		err = errno
	} else if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, leader.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); errno != 0 {
		err = errno
	} else {
		follower, err = os.OpenFile("/dev/pts/"+strconv.Itoa(int(n)), os.O_RDWR|syscall.O_NOCTTY, 0)
	}
	if err != nil {
		leader.Close()
		return nil, nil, err
	}
	return leader, follower, nil
}
