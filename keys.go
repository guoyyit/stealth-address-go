package stealth

import (
	"bytes"
	"math/big"
)

// Scalar is a big-endian elliptic-curve scalar in [1, N).
type Scalar [32]byte

// MasterKey is a receiver's long-lived master secret. The service never
// sees it: scan and spend keys are deterministically derived from it for
// each receiver identity.
type MasterKey struct {
	secret [32]byte
}

// KeyPair holds a receiver's private scan (view) and spend keys together
// with their corresponding public keys.
type KeyPair struct {
	ScanPriv  Scalar
	SpendPriv Scalar
	ScanPub   []byte
	SpendPub  []byte
}

// PublicKeySet contains only the public scan and spend keys stored by the
// service during registration. No private material is persisted.
type PublicKeySet struct {
	ScanPub  []byte
	SpendPub []byte
}

const (
	domainMaster = "stealth-go/v1/master"
	domainScan   = "stealth-go/v1/scan-key"
	domainSpend  = "stealth-go/v1/spend-key"
	domainOutput = "stealth-go/v1/output-key"
)

// PublicOnly returns the public portion of the key pair.
func (kp *KeyPair) PublicOnly() *PublicKeySet {
	return &PublicKeySet{
		ScanPub:  cloneBytes(kp.ScanPub),
		SpendPub: cloneBytes(kp.SpendPub),
	}
}

// Equal reports whether two public key sets contain identical keys.
func (p *PublicKeySet) Equal(other *PublicKeySet) bool {
	return bytes.Equal(p.ScanPub, other.ScanPub) &&
		bytes.Equal(p.SpendPub, other.SpendPub)
}

// GenerateMasterKey creates a new random master secret.
func GenerateMasterKey() (*MasterKey, error) {
	k, err := randScalar(randomReader())
	if err != nil {
		return nil, err
	}
	return &MasterKey{secret: scalarBytes(k)}, nil
}

// NewMasterKeyFromSeed reconstructs a master key from its exported Seed
// material (a 32-byte nonzero scalar), intended for key backup/recovery.
// The seed must be kept secret and should originate from
// GenerateMasterKey + Seed or comparable high-entropy sampling.
func NewMasterKeyFromSeed(seed []byte) *MasterKey {
	var mk MasterKey
	if len(seed) != 32 {
		return nil
	}
	copy(mk.secret[:], seed)
	if _, ok := scalarFromBytes(mk.secret[:]); !ok {
		return nil
	}
	return &mk
}

// Seed exports the master secret material; it must be kept private.
func (mk *MasterKey) Seed() []byte {
	return append([]byte(nil), mk.secret[:]...)
}

// DeriveKeyPair deterministically derives the scan and spend key pair for
// receiverID from the master secret. The same master secret and receiverID
// always produce the same key pair.
func DeriveKeyPair(mk *MasterKey, receiverID string) (*KeyPair, error) {
	if mk == nil {
		return nil, ErrInvalidArgument
	}
	id := []byte(receiverID)
	scanK := hashToScalar(domainScan, mk.secret[:], id)
	spendK := hashToScalar(domainSpend, mk.secret[:], id)

	scanX, scanY := baseMult(scanK)
	spendX, spendY := baseMult(spendK)

	return &KeyPair{
		ScanPriv:  scalarBytes(scanK),
		SpendPriv: scalarBytes(spendK),
		ScanPub:   marshalPoint(scanX, scanY),
		SpendPub:  marshalPoint(spendX, spendY),
	}, nil
}

func scalarValue(s Scalar) (*big.Int, bool) {
	return scalarFromBytes(s[:])
}

func cloneBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}
