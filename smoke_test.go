package stealth

import (
	"testing"
)

func TestSmokeRoundtrip(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	mk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := DeriveKeyPair(mk, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RegisterReceiver("alice", kp); err != nil {
		t.Fatal(err)
	}

	addr, err := svc.GenerateAddress("alice")
	if err != nil {
		t.Fatal(err)
	}
	rec := OutputRecord{
		ID:           []byte("out-1"),
		EphemeralPub: addr.EphemeralPub,
		OneTimePub:   addr.OneTimePub,
		Amount:       42,
	}
	if err := svc.SubmitOutput(rec); err != nil {
		t.Fatal(err)
	}

	report, err := svc.Scan("alice", kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Outputs) != 1 {
		t.Fatalf("want 1 match, got %d", len(report.Outputs))
	}

	priv, err := svc.Recover("alice", []byte("out-1"), kp)
	if err != nil {
		t.Fatal(err)
	}
	// priv*G must equal the one-time public key.
	p, ok := scalarValue(priv)
	if !ok {
		t.Fatal("bad recovered scalar")
	}
	x, y := baseMult(p)
	if got := marshalPoint(x, y); !equalBytes(got, addr.OneTimePub) {
		t.Fatal("recovered key does not match one-time address")
	}
}
