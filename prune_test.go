package stealth

import "testing"

func TestPruneExplicitErrorAndRescan(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()

	// 5 outputs; scan through seq 5.
	for i := 0; i < 5; i++ {
		e.submit(t, "q"+itoa(i))
	}
	r, err := e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Outputs) != 5 {
		t.Fatalf("want 5, got %d", len(r.Outputs))
	}

	// Prune seq < 4: q0,q1,q2 (seq 1,2,3) removed; q3+ retained.
	if err := e.svc.Prune(4); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.svc.stream.findID([]byte("q2")); ok {
		t.Fatal("pruned output still indexed")
	}
	if _, ok := e.svc.stream.findID([]byte("q3")); !ok {
		t.Fatal("retained output missing")
	}

	// Recovery of pruned metadata is explicit, not silent.
	if _, err := e.svc.Recover("alice", []byte("q0"), e.kp); err != ErrOutputNotFound {
		t.Fatalf("want ErrOutputNotFound for pruned output, got %v", err)
	}

	// Incremental scan with cursor 5 >= frontier 4 still works and finds
	// newly arriving outputs.
	e.submit(t, "q5")
	r, err = e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if ids := reportIDs(r); len(ids) != 1 || ids[0] != "q5" {
		t.Fatalf("want [q5], got %v", ids)
	}

	// Rescan deterministically returns all retained owned outputs.
	r, err = e.svc.Rescan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, m := range r.Outputs {
		got[string(m.Record.ID)] = true
	}
	for _, want := range []string{"q3", "q4", "q5"} {
		if !got[want] {
			t.Fatalf("rescan missing retained output %s: %v", want, reportIDs(r))
		}
	}
	if got["q0"] || got["q1"] || got["q2"] {
		t.Fatalf("rescan must not recover pruned outputs: %v", reportIDs(r))
	}

	// After rescan, an ordinary incremental scan reports nothing.
	r, err = e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Outputs) != 0 {
		t.Fatalf("post-rescan incremental scan must be empty: %v", reportIDs(r))
	}
}

func TestPruneBehindCursorIsExplicit(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	mk, _ := GenerateMasterKey()
	kp, _ := DeriveKeyPair(mk, "alice")
	if err := svc.RegisterReceiver("alice", kp); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		a, _ := svc.GenerateAddress("alice")
		if err := svc.SubmitOutput(OutputRecord{
			ID:           []byte("z" + itoa(i)),
			EphemeralPub: a.EphemeralPub,
			OneTimePub:   a.OneTimePub,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Scan("alice", kp.ScanPriv); err != nil {
		t.Fatal(err)
	}
	// Prune beyond the committed cursor (seq 6); next Scan must refuse.
	if err := svc.Prune(4); err != nil {
		t.Fatal(err)
	}
	// cursor=6, retained=4: 6 >= 4, so scan still works (committed range
	// partially overlaps pruned tail but cursor is ahead). Append new one.
	a, _ := svc.GenerateAddress("alice")
	if err := svc.SubmitOutput(OutputRecord{
		ID:           []byte("z6"),
		EphemeralPub: a.EphemeralPub,
		OneTimePub:   a.OneTimePub,
	}); err != nil {
		t.Fatal(err)
	}
	r, err := svc.Scan("alice", kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if ids := reportIDs(r); len(ids) != 1 || ids[0] != "z6" {
		t.Fatalf("want [z6], got %v", ids)
	}

	// Now create a second receiver with a cursor at 3 and prune past it.
	mk2, _ := GenerateMasterKey()
	kp2, _ := DeriveKeyPair(mk2, "bob")
	if err := svc.RegisterReceiver("bob", kp2); err != nil {
		t.Fatal(err)
	}
	st, err := openScanState(dir, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.commit(scanCursor{Seq: 3}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Prune(6); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Scan("bob", kp2.ScanPriv); err != ErrPrunedData {
		t.Fatalf("want ErrPrunedData for cursor behind frontier, got %v", err)
	}
	// Rescan is the explicit recovery path and succeeds from seq 6.
	r2, err := svc.Rescan("bob", kp2.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	// bob owns none of alice's outputs.
	if len(r2.Outputs) != 0 {
		t.Fatalf("bob should own nothing, got %v", reportIDs(r2))
	}
	// After rescan the cursor moved to the frontier, incremental scan is ok.
	if _, err := svc.Scan("bob", kp2.ScanPriv); err != nil {
		t.Fatalf("post-rescan scan failed: %v", err)
	}
}

func TestNewReceiverStartsAtFrontierAfterPrune(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()
	e.submit(t, "old")
	if _, err := e.svc.Scan("alice", e.kp.ScanPriv); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Prune(10); err != nil {
		t.Fatal(err)
	}
	// A brand new receiver has cursor 0 (never scanned); it starts at the
	// retained frontier without an ErrPrunedData error.
	mk2, _ := GenerateMasterKey()
	kp2, _ := DeriveKeyPair(mk2, "carol")
	if err := e.svc.RegisterReceiver("carol", kp2); err != nil {
		t.Fatal(err)
	}
	a, _ := e.svc.GenerateAddress("carol")
	if err := e.svc.SubmitOutput(OutputRecord{
		ID:           []byte("new"),
		EphemeralPub: a.EphemeralPub,
		OneTimePub:   a.OneTimePub,
	}); err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.Scan("carol", kp2.ScanPriv)
	if err != nil {
		t.Fatalf("new receiver scan must not fail on prune: %v", err)
	}
	if ids := reportIDs(r); len(ids) != 1 || ids[0] != "new" {
		t.Fatalf("want [new], got %v", ids)
	}
}

func TestPruneSequenceNumbersNotReused(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()
	e.submit(t, "a")
	e.submit(t, "b")
	if err := e.svc.Prune(3); err != nil {
		t.Fatal(err)
	}
	e.submit(t, "c")
	seq, ok := e.svc.stream.findID([]byte("c"))
	if !ok {
		t.Fatal("c missing")
	}
	if seq != 3 {
		t.Fatalf("sequence numbers reused after prune: c at %d, want 3", seq)
	}
}
