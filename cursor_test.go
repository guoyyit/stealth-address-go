package stealth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCursorMonotonicCommit(t *testing.T) {
	dir := t.TempDir()
	st, err := openScanState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if cur, _ := st.load(); cur.Seq != 0 {
		t.Fatal("new cursor must be zero")
	}
	if err := st.commit(scanCursor{Seq: 10}); err != nil {
		t.Fatal(err)
	}
	if err := st.commit(scanCursor{Seq: 9}); err != ErrInvalidArgument {
		t.Fatalf("rewind must fail, got %v", err)
	}
	if err := st.commit(scanCursor{Seq: 10}); err != nil {
		t.Fatalf("equal commit should be no-op, got %v", err)
	}
	if cur, _ := st.load(); cur.Seq != 10 {
		t.Fatalf("cursor changed unexpectedly: %d", cur.Seq)
	}

	// Persistence across reopen.
	st2, err := openScanState(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if cur, _ := st2.load(); cur.Seq != 10 {
		t.Fatalf("cursor not persisted: %d", cur.Seq)
	}
}

func TestReceiverIDPathTraversalIsContained(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	mk, _ := GenerateMasterKey()
	kp, _ := DeriveKeyPair(mk, "../escape")
	if err := svc.RegisterReceiver("../escape", kp); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Scan("../escape", kp.ScanPriv); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnregisterReceiver("../escape"); err != nil {
		t.Fatal(err)
	}

	// No file may have escaped the data directory.
	if _, err := os.Stat(filepath.Join(dir, "..", "escape.cursor")); !os.IsNotExist(err) {
		t.Fatal("cursor escaped the scans directory")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "scans"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "..") || strings.Contains(e.Name(), "escape") {
			t.Fatalf("unexpected raw receiver id on disk: %s", e.Name())
		}
	}
}
