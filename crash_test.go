package stealth

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCrashRecoveryReopensState verifies that reopening the service
// restores registry, outputs and scan cursors, so already-committed
// discoveries are not reported again and no durable output is lost.
func TestCrashRecoveryReopensState(t *testing.T) {
	dir := t.TempDir()

	mk, _ := GenerateMasterKey()
	kp, _ := DeriveKeyPair(mk, "alice")

	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RegisterReceiver("alice", kp); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		a, _ := svc.GenerateAddress("alice")
		if err := svc.SubmitOutput(OutputRecord{
			ID:           []byte("p" + itoa(i)),
			EphemeralPub: a.EphemeralPub,
			OneTimePub:   a.OneTimePub,
		}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := svc.Scan("alice", kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Outputs) != 5 {
		t.Fatalf("want 5 matches, got %d", len(r.Outputs))
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate crash: a fresh process opens the same directory.
	svc2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	r2, err := svc2.Scan("alice", kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Outputs) != 0 {
		t.Fatalf("committed scan must not replay after reopen, got %v", reportIDs(r2))
	}

	// Outputs arriving after the crash are picked up exactly once.
	for i := 5; i < 8; i++ {
		a, _ := svc2.GenerateAddress("alice")
		if err := svc2.SubmitOutput(OutputRecord{
			ID:           []byte("p" + itoa(i)),
			EphemeralPub: a.EphemeralPub,
			OneTimePub:   a.OneTimePub,
		}); err != nil {
			t.Fatal(err)
		}
	}
	r3, err := svc2.Scan("alice", kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if ids := reportIDs(r3); len(ids) != 3 {
		t.Fatalf("want 3 new outputs, got %v", ids)
	}

	// Recovery still works across reopen.
	priv, err := svc2.Recover("alice", []byte("p0"), kp)
	if err != nil {
		t.Fatal(err)
	}
	seq, _ := svc2.stream.findID([]byte("p0"))
	rec, _ := svc2.stream.recordAt(seq)
	p, ok := scalarValue(priv)
	if !ok {
		t.Fatal("bad recovered scalar")
	}
	x, y := baseMult(p)
	if !equalBytes(marshalPoint(x, y), rec.OneTimePub) {
		t.Fatal("post-crash recovery produced wrong key")
	}
}

// TestPartialWriteIsTruncated appends garbage bytes to the log tail and
// verifies reopen truncates them instead of surfacing a partial record.
func TestPartialWriteIsTruncated(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{svc: svc, kp: mustRegister(t, svc, "alice")}
	e.submit(t, "ok1")
	e.submit(t, "ok2")
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, streamFileName)
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{frameMagic0, frameMagic1, 0, 0, 0, 9, 'p', 'a', 'r', 't'}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	svc2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	fi2, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi2.Size() != fi.Size() {
		t.Fatalf("partial tail not truncated: %d != %d", fi2.Size(), fi.Size())
	}
	seq, ok := svc2.stream.findID([]byte("ok1"))
	if !ok {
		t.Fatal("ok1 lost after partial-write recovery")
	}
	if _, ok := svc2.stream.recordAt(seq); !ok {
		t.Fatal("record unreadable after recovery")
	}

	// New appends remain possible after recovery and keep sequence numbers.
	e2 := &testEnv{svc: svc2, kp: e.kp}
	e2.submit(t, "ok3")
	if svc2.stream.lastSeq() != 3 {
		t.Fatalf("want lastSeq 3, got %d", svc2.stream.lastSeq())
	}
}

func mustRegister(t *testing.T, svc *Service, id string) *KeyPair {
	t.Helper()
	mk, _ := GenerateMasterKey()
	kp, err := DeriveKeyPair(mk, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RegisterReceiver(id, kp); err != nil {
		t.Fatal(err)
	}
	return kp
}
