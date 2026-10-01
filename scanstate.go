package stealth

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
)

// scanCursor points at the first output sequence number not yet scanned.
// Seq=0 means "nothing scanned yet" (scan starts at the stream's first
// available record).
type scanCursor struct {
	Seq uint64
}

const cursorMagic = "STCURSOR01\n"

type scanState struct {
	mu   sync.Mutex
	path string
}

func scanStatePath(dir, receiverID string) string {
	sum := sha256.Sum256([]byte(receiverID))
	name := encodeHex(sum[:]) + ".cursor"
	return filepath.Join(dir, "scans", name)
}

func openScanState(dir, receiverID string) (*scanState, error) {
	path := scanStatePath(dir, receiverID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	st := &scanState{path: path}
	if _, err := st.load(); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *scanState) load() (scanCursor, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.loadLocked()
}

func (st *scanState) loadLocked() (scanCursor, error) {
	data, err := os.ReadFile(st.path)
	if os.IsNotExist(err) {
		return scanCursor{}, nil
	}
	if err != nil {
		return scanCursor{}, err
	}
	magic := []byte(cursorMagic)
	if len(data) != len(magic)+8 {
		return scanCursor{}, ErrCorruptStorage
	}
	if string(data[:len(magic)]) != cursorMagic {
		return scanCursor{}, ErrCorruptStorage
	}
	return scanCursor{Seq: binary.BigEndian.Uint64(data[len(magic):])}, nil
}

// storeLocked writes the cursor atomically (temp + fsync + rename).
func (st *scanState) storeLocked(cur scanCursor) error {
	buf := make([]byte, len(cursorMagic)+8)
	copy(buf, cursorMagic)
	binary.BigEndian.PutUint64(buf[len(cursorMagic):], cur.Seq)

	tmp := st.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, st.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(st.path))
}

// commit advances the cursor. Advances are only accepted monotonically, so
// concurrent scans for the same receiver can never move the cursor
// backwards or double-report committed ranges.
func (st *scanState) commit(cur scanCursor) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	prev, err := st.loadLocked()
	if err != nil {
		return err
	}
	if cur.Seq < prev.Seq {
		return ErrInvalidArgument
	}
	if cur.Seq == prev.Seq {
		return nil
	}
	return st.storeLocked(cur)
}

func (st *scanState) reset(cur scanCursor) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.storeLocked(cur)
}

func (st *scanState) close() error {
	return nil
}

func (st *scanState) remove() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := os.Remove(st.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(st.path + ".tmp"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(filepath.Dir(st.path))
}
