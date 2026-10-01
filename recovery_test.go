package stealth

import (
	"errors"
	"sync"
	"testing"
)

func TestViewKeyOnlyCannotSpend(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()
	e.submit(t, "x")
	if _, err := e.svc.Scan("alice", e.kp.ScanPriv); err != nil {
		t.Fatal(err)
	}

	forged := *e.kp
	forged.SpendPriv = Scalar{}
	if _, err := e.svc.Recover("alice", []byte("x"), &forged); err != ErrInvalidArgument {
		t.Fatalf("want ErrInvalidArgument for zero spend scalar, got %v", err)
	}

	randomK, err := randScalar(randomReader())
	if err != nil {
		t.Fatal(err)
	}
	rx, ry := baseMult(randomK)
	forged.SpendPriv = scalarBytes(randomK)
	forged.SpendPub = marshalPoint(rx, ry)
	if _, err := e.svc.Recover("alice", []byte("x"), &forged); err != ErrSpendKeyMismatch {
		t.Fatalf("want ErrSpendKeyMismatch, got %v", err)
	}

	other, _ := randScalar(randomReader())
	forged2 := *e.kp
	forged2.ScanPriv = scalarBytes(other)
	if _, err := e.svc.Recover("alice", []byte("x"), &forged2); !errors.Is(err, ErrViewKeyMismatch) {
		t.Fatalf("want ErrViewKeyMismatch, got %v", err)
	}
	if _, err := e.svc.Scan("alice", forged2.ScanPriv); err != ErrViewKeyMismatch {
		t.Fatalf("scan with wrong view key: want ErrViewKeyMismatch, got %v", err)
	}
}

func TestRecoverErrorDistinction(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()
	e.submit(t, "x")

	if _, err := e.svc.Recover("ghost", []byte("x"), e.kp); err != ErrReceiverNotFound {
		t.Fatalf("want ErrReceiverNotFound, got %v", err)
	}
	if _, err := e.svc.Recover("alice", []byte("missing"), e.kp); err != ErrOutputNotFound {
		t.Fatalf("want ErrOutputNotFound, got %v", err)
	}
	if _, err := e.svc.Recover("alice", nil, e.kp); err != ErrInvalidArgument {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}

	mk2, _ := GenerateMasterKey()
	kp2, _ := DeriveKeyPair(mk2, "mallory")
	a, _ := GenerateStealthAddress(kp2.PublicOnly(), randomReader())
	if err := e.svc.SubmitOutput(OutputRecord{
		ID:           []byte("f"),
		EphemeralPub: a.EphemeralPub,
		OneTimePub:   a.OneTimePub,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Recover("alice", []byte("f"), e.kp); err != ErrNotOwner {
		t.Fatalf("want ErrNotOwner, got %v", err)
	}

	if _, err := RecoverOneTimePrivateKey(e.kp, a.EphemeralPub, a.OneTimePub); err != ErrNotOwner {
		t.Fatalf("want ErrNotOwner, got %v", err)
	}
	if _, err := RecoverOneTimePrivateKey(nil, nil, nil); err != ErrInvalidArgument {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}
	if _, err := RecoverOneTimePrivateKey(e.kp, nil, nil); err != ErrInvalidAddress {
		t.Fatalf("want ErrInvalidAddress, got %v", err)
	}
}

func TestSubmitValidation(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()

	if err := e.svc.SubmitOutput(OutputRecord{}); err != ErrInvalidArgument {
		t.Fatalf("want ErrInvalidArgument for empty ID, got %v", err)
	}
	a, _ := e.svc.GenerateAddress("alice")
	bad := OutputRecord{ID: []byte("bad"), EphemeralPub: a.EphemeralPub, OneTimePub: make([]byte, 33)}
	if err := e.svc.SubmitOutput(bad); err != ErrInvalidAddress {
		t.Fatalf("want ErrInvalidAddress for bad point, got %v", err)
	}

	good := OutputRecord{ID: []byte("g"), EphemeralPub: a.EphemeralPub, OneTimePub: a.OneTimePub}
	if err := e.svc.SubmitOutput(good); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SubmitOutput(good); err != ErrOutputExists {
		t.Fatalf("want ErrOutputExists, got %v", err)
	}
	if n := len(e.svc.stream.records); n != 1 {
		t.Fatalf("want 1 stored record, got %d", n)
	}
}

func TestUnregisterDuringScan(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()
	e.submit(t, "a")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = e.svc.Scan("alice", e.kp.ScanPriv)
		}
	}()
	go func() {
		defer wg.Done()
		_ = e.svc.UnregisterReceiver("alice")
	}()
	wg.Wait()

	if _, err := e.svc.Scan("alice", e.kp.ScanPriv); err != ErrReceiverNotFound {
		t.Fatalf("want ErrReceiverNotFound after unregister, got %v", err)
	}
}

func TestConcurrentScansNoDuplicates(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()
	for i := 0; i < 200; i++ {
		e.submit(t, "c"+itoa(i))
	}

	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := e.svc.Scan("alice", e.kp.ScanPriv)
			if err != nil {
				t.Errorf("scan: %v", err)
				return
			}
			mu.Lock()
			for _, m := range r.Outputs {
				seen[string(m.Record.ID)]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(seen) != 200 {
		t.Fatalf("want exactly 200 distinct outputs, got %d", len(seen))
	}
	for id, count := range seen {
		if count > 1 {
			t.Fatalf("output %s reported %d times", id, count)
		}
	}
}

func TestConcurrentRegisterUnregister(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "r" + itoa(i)
			mk, _ := GenerateMasterKey()
			kp, _ := DeriveKeyPair(mk, id)
			_ = svc.RegisterReceiver(id, kp)
			_, _ = svc.GenerateAddress(id)
			_, _ = svc.Scan(id, kp.ScanPriv)
		}(i)
	}
	wg.Wait()

	if ids := svc.registry.list(); len(ids) != 8 {
		t.Fatalf("want 8 receivers, got %d", len(ids))
	}

	// Reopen and verify the registry survived.
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	if ids := svc2.registry.list(); len(ids) != 8 {
		t.Fatalf("after reopen want 8 receivers, got %d", len(ids))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}
