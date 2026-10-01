package stealth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCorruptMagicDetected(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{svc: svc, kp: mustRegister(t, svc, "alice")}
	e.submit(t, "x")
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, streamFileName)
	f, err := os.OpenFile(logPath, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xff, 0xff}, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(Config{Dir: dir}); err != ErrCorruptStorage {
		t.Fatalf("want ErrCorruptStorage on bad magic, got %v", err)
	}
}

func TestPrunePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	kp := mustRegister(t, svc, "alice")
	for i := 0; i < 4; i++ {
		a, _ := svc.GenerateAddress("alice")
		if err := svc.SubmitOutput(OutputRecord{
			ID:           []byte("m" + itoa(i)),
			EphemeralPub: a.EphemeralPub,
			OneTimePub:   a.OneTimePub,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.Prune(3); err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	svc2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	first, frontier := svc2.stream.retainedSeq()
	if first != 3 {
		t.Fatalf("retained frontier not persisted: %d", first)
	}
	if frontier != 5 {
		t.Fatalf("frontier should continue after prune, got %d", frontier)
	}
	if _, ok := svc2.stream.findID([]byte("m0")); ok {
		t.Fatal("pruned record survived reopen")
	}

	// Sequence numbers continue past the gap.
	a, _ := svc2.GenerateAddress("alice")
	if err := svc2.SubmitOutput(OutputRecord{
		ID:           []byte("m4"),
		EphemeralPub: a.EphemeralPub,
		OneTimePub:   a.OneTimePub,
	}); err != nil {
		t.Fatal(err)
	}
	seq, _ := svc2.stream.findID([]byte("m4"))
	if seq != 5 {
		t.Fatalf("want seq 5, got %d", seq)
	}

	// Rescan on reopen covers retained range only.
	r, err := svc2.Rescan("alice", kp.ScanPriv)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, m := range r.Outputs {
		got[string(m.Record.ID)] = true
	}
	if !got["m3"] || !got["m4"] || got["m0"] {
		t.Fatalf("unexpected rescan set after reopen: %v", reportIDs(r))
	}
}

func TestRegistryNoPartialWrite(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		mk, _ := GenerateMasterKey()
		kp, _ := DeriveKeyPair(mk, "u"+itoa(i))
		if err := svc.RegisterReceiver("u"+itoa(i), kp); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	// No temp file may linger; the registry must be complete JSON.
	if _, err := os.Stat(filepath.Join(dir, registryFileName+".tmp")); !os.IsNotExist(err) {
		t.Fatal("registry temp file left behind")
	}
	svc2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	if len(svc2.registry.list()) != 10 {
		t.Fatal("registry lost entries after reopen")
	}
}

func TestConcurrentAddressGeneration(t *testing.T) {
	e := newEnv(t, "alice")
	defer e.svc.Close()

	const n = 64
	addrs := make(chan *StealthAddress, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			a, err := e.svc.GenerateAddress("alice")
			if err != nil {
				errs <- err
				return
			}
			addrs <- a
		}()
	}

	seenR := map[string]bool{}
	seenP := map[string]bool{}
	collected := 0
	for collected < n {
		select {
		case a := <-addrs:
			rs := string(a.EphemeralPub)
			ps := string(a.OneTimePub)
			if seenR[rs] || seenP[ps] {
				t.Fatal("concurrent address generation produced a duplicate")
			}
			seenR[rs] = true
			seenP[ps] = true
			collected++
		case err := <-errs:
			t.Fatal(err)
		}
	}
}
