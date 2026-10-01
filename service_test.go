package stealth

import "testing"

type testEnv struct {
	svc *Service
	kp  *KeyPair
}

func newEnv(t *testing.T, id string) *testEnv {
	t.Helper()
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	mk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := DeriveKeyPair(mk, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RegisterReceiver(id, kp); err != nil {
		t.Fatal(err)
	}
	return &testEnv{svc: svc, kp: kp}
}

func (e *testEnv) submit(t *testing.T, id string) {
	t.Helper()
	a, err := e.svc.GenerateAddress("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SubmitOutput(OutputRecord{
		ID:           []byte(id),
		EphemeralPub: a.EphemeralPub,
		OneTimePub:   a.OneTimePub,
		Amount:       1,
	}); err != nil {
		t.Fatal(err)
	}
}

func reportIDs(r *ScanReport) []string {
	out := make([]string, 0, len(r.Outputs))
	for _, m := range r.Outputs {
		out = append(out, string(m.Record.ID))
	}
	return out
}

func TestRegisterDuplicateAndUnknownReceiver(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()

	if err := e.svc.RegisterReceiver("alice", e.kp); err != ErrReceiverExists {
		t.Fatalf("want ErrReceiverExists, got %v", err)
	}
	if _, err := e.svc.GenerateAddress("nobody"); err != ErrReceiverNotFound {
		t.Fatalf("want ErrReceiverNotFound, got %v", err)
	}
}

func TestSubmitAndIncrementalScan(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()

	r, err := e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Outputs) != 0 {
		t.Fatal("empty stream must report no outputs")
	}

	e.submit(t, "a")
	e.submit(t, "b")

	r, err = e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if ids := reportIDs(r); len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("want [a b], got %v", ids)
	}

	r, err = e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Outputs) != 0 {
		t.Fatalf("incremental scan must not replay, got %v", reportIDs(r))
	}

	for _, id := range []string{"a", "b"} {
		priv, err := e.svc.Recover("alice", []byte(id), e.kp)
		if err != nil {
			t.Fatalf("recover %s: %v", id, err)
		}
		p, _ := scalarValue(priv)
		seq, ok := e.svc.stream.findID([]byte(id))
		if !ok {
			t.Fatal("output missing from stream")
		}
		rec, _ := e.svc.stream.recordAt(seq)
		x, y := baseMult(p)
		if !equalBytes(marshalPoint(x, y), rec.OneTimePub) {
			t.Fatalf("recovered key for %s does not satisfy p*G == P", id)
		}
	}
}

func TestOutOfOrderAndDuplicates(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()

	var recs []OutputRecord
	for _, id := range []string{"o1", "o2", "o3"} {
		a, err := e.svc.GenerateAddress("alice")
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, OutputRecord{
			ID:           []byte(id),
			EphemeralPub: a.EphemeralPub,
			OneTimePub:   a.OneTimePub,
		})
	}
	order := []int{2, 0, 1, 2}
	var dupErrCount int
	for _, i := range order {
		err := e.svc.SubmitOutput(recs[i])
		if err == ErrOutputExists {
			dupErrCount++
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if dupErrCount != 1 {
		t.Fatalf("want one duplicate rejection, got %d", dupErrCount)
	}

	r, err := e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	ids := reportIDs(r)
	gotSet := map[string]bool{}
	for _, id := range ids {
		if gotSet[id] {
			t.Fatalf("id %s reported twice", id)
		}
		gotSet[id] = true
	}
	if len(ids) != 3 || !gotSet["o1"] || !gotSet["o2"] || !gotSet["o3"] {
		t.Fatalf("duplicate/out-of-order mishandled: %v", ids)
	}

	mk2, _ := GenerateMasterKey()
	kp2, _ := DeriveKeyPair(mk2, "mallory")
	foreign, err := GenerateStealthAddress(kp2.PublicOnly(), randomReader())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SubmitOutput(OutputRecord{
		ID:           []byte("foreign"),
		EphemeralPub: foreign.EphemeralPub,
		OneTimePub:   foreign.OneTimePub,
	}); err != nil {
		t.Fatal(err)
	}

	r, err = e.svc.Scan("alice", e.kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Outputs) != 0 {
		t.Fatalf("foreign output reported: %v", reportIDs(r))
	}

	if err := e.svc.RegisterReceiver("mallory", kp2); err != nil {
		t.Fatal(err)
	}
	r, err = e.svc.Scan("mallory", kp2.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if ids := reportIDs(r); len(ids) != 1 || ids[0] != "foreign" {
		t.Fatalf("mallory should see only foreign, got %v", ids)
	}
}
