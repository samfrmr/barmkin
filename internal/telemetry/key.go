package telemetry

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Daviey/barmkin/internal/proto"
)

// KeySize is the size of the pseudonym key in bytes.
const KeySize = 32

// keyFile is the pseudonym key's name in the monitor's state directory.
const keyFile = "telemetry.key"

// lineageDomain separates lineage pseudonyms from any other use of the key.
const lineageDomain = "barmkin.telemetry.lineage.v1"

// LoadKey returns the pseudonym key kept in stateDir, creating it on first
// use. The key is a private regular file of this uid (0600), so it lives and
// dies with the monitor's state, and a lineage keeps its pseudonym across
// restarts. A key file that is a symlink, not a regular file, not this
// uid's, readable by group or other, or of the wrong size is refused.
func LoadKey(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, keyFile)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return createKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("open telemetry key: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("telemetry key %s is not a regular file", path)
	case owner(fi) != os.Geteuid():
		return nil, fmt.Errorf("telemetry key %s is not owned by this uid", path)
	case fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("telemetry key %s has mode %#o; it must be private", path, fi.Mode().Perm())
	}
	key, err := io.ReadAll(io.LimitReader(f, KeySize+1))
	if err != nil {
		return nil, fmt.Errorf("read telemetry key: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("telemetry key %s is not %d bytes", path, KeySize)
	}
	return key, nil
}

func createKey(path string) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create telemetry key: %w", err)
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = syncDir(filepath.Dir(path))
	}
	if err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("write telemetry key: %w", err)
	}
	return key, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lineageID is the pseudonym of the lineage (uid, host, root): the first 16
// bytes of an HMAC-SHA256 under key, in hex.
func lineageID(key []byte, uid uint32, host proto.Host, root string) string {
	mac := hmac.New(sha256.New, key)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uid)
	mac.Write([]byte(lineageDomain))
	mac.Write([]byte{0})
	mac.Write(b[:])
	mac.Write([]byte(host))
	mac.Write([]byte{0})
	mac.Write([]byte(root))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
