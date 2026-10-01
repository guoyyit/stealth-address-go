package stealth

import "testing"

func TestKeyDerivationDeterministic(t *testing.T) {
	mk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k1, err := DeriveKeyPair(mk, "bob")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKeyPair(mk, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if k1.ScanPriv != k2.ScanPriv || k1.SpendPriv != k2.SpendPriv {
		t.Fatal("derivation not deterministic")
	}

	// Different identities under the same master must differ.
	k3, err := DeriveKeyPair(mk, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if k1.ScanPriv == k3.ScanPriv || k1.SpendPriv == k3.SpendPriv {
		t.Fatal("derived keys for distinct identities collide")
	}

	// Public keys correspond to private keys.
	for _, kp := range []*KeyPair{k1, k3} {
		sv, ok := scalarValue(kp.ScanPriv)
		if !ok {
			t.Fatal("bad scan scalar")
		}
		bv, ok := scalarValue(kp.SpendPriv)
		if !ok {
			t.Fatal("bad spend scalar")
		}
		if got := marshalPoint(baseMult(sv)); !equalBytes(got, kp.ScanPub) {
			t.Fatal("scan public key mismatch")
		}
		if got := marshalPoint(baseMult(bv)); !equalBytes(got, kp.SpendPub) {
			t.Fatal("spend public key mismatch")
		}
		if equalBytes(kp.ScanPub, kp.SpendPub) {
			t.Fatal("scan and spend public keys must differ")
		}
	}

	// Seed reconstruction reproduces the master key.
	mk2 := NewMasterKeyFromSeed(mk.Seed())
	k4, err := DeriveKeyPair(mk2, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if k4.ScanPriv != k1.ScanPriv {
		t.Fatal("master seed reconstruction failed")
	}
}

func TestStealthAddressUnlinkability(t *testing.T) {
	mkA, _ := GenerateMasterKey()
	mkB, _ := GenerateMasterKey()
	kpA, _ := DeriveKeyPair(mkA, "alice")
	kpB, _ := DeriveKeyPair(mkB, "eve")
	pubA := kpA.PublicOnly()

	const n = 8
	addrs := make([]*StealthAddress, n)
	for i := range addrs {
		a, err := GenerateStealthAddress(pubA, randomReader())
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = a
	}

	// 1. Same receiver: no shared bytes across one-time keys/ephemerals.
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if equalBytes(addrs[i].OneTimePub, addrs[j].OneTimePub) {
				t.Fatalf("addresses %d,%d share one-time pubkey", i, j)
			}
			if equalBytes(addrs[i].EphemeralPub, addrs[j].EphemeralPub) {
				t.Fatalf("addresses %d,%d share ephemeral pubkey", i, j)
			}
		}
	}

	// 2. Nothing on the wire equals the receiver's public keys.
	for _, a := range addrs {
		if equalBytes(a.OneTimePub, pubA.ScanPub) || equalBytes(a.OneTimePub, pubA.SpendPub) {
			t.Fatal("one-time key leaks identity key")
		}
		if equalBytes(a.EphemeralPub, pubA.ScanPub) || equalBytes(a.EphemeralPub, pubA.SpendPub) {
			t.Fatal("ephemeral key leaks identity key")
		}
	}

	// 3. A non-owner view key must not match any of alice's addresses.
	vB, _ := scalarValue(kpB.ScanPriv)
	bxB, byB, _ := parsePoint(kpB.SpendPub)
	for _, a := range addrs {
		rx, ry, _ := parsePoint(a.EphemeralPub)
		px, py, _ := parsePoint(a.OneTimePub)
		if _, owned := matchOutput(vB, bxB, byB, rx, ry, px, py); owned {
			t.Fatal("foreign view key matched owner address")
		}
	}

	// 4. Owner view key matches every address, foreign does not.
	vA, _ := scalarValue(kpA.ScanPriv)
	bxA, byA, _ := parsePoint(kpA.SpendPub)
	for _, a := range addrs {
		rx, ry, _ := parsePoint(a.EphemeralPub)
		px, py, _ := parsePoint(a.OneTimePub)
		if _, owned := matchOutput(vA, bxA, byA, rx, ry, px, py); !owned {
			t.Fatal("owner view key failed to match own address")
		}
	}

	// 5. Labels differ for distinct addresses.
	labels := map[string]bool{}
	for _, a := range addrs {
		l := EncodeStealthAddress(a)
		if labels[l] {
			t.Fatal("duplicate address labels")
		}
		labels[l] = true
	}
}

func TestParseRejectsJunk(t *testing.T) {
	if _, err := ParseStealthAddress(nil, nil); err != ErrInvalidAddress {
		t.Fatalf("want ErrInvalidAddress, got %v", err)
	}
	if _, err := ParseStealthAddress(make([]byte, 33), make([]byte, 33)); err != ErrInvalidAddress {
		t.Fatalf("want ErrInvalidAddress for malformed points, got %v", err)
	}
}
