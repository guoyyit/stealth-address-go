package stealth

import (
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
)

const (
	masterKeyLen = 32

	// hkdfSalt is the fixed application domain for key derivation.
	hkdfSalt = "stealth-address-go/v1"

	spendDerivationDomain = "spend"
	viewDerivationDomain  = "view"
)

// MasterKey is the receiver root secret held only by the receiver.
// Spend and view secrets are derived deterministically from it.
type MasterKey struct {
	secret [32]byte
}

// NewMasterKey draws a fresh 256-bit master key from rng.
func NewMasterKey(rng io.Reader) (*MasterKey, error) {
	var m MasterKey
	if _, err := io.ReadFull(rng, m.secret[:]); err != nil {
		return nil, err
	}
	return &m, nil
}

// MasterKeyFromBytes restores a master key from exactly 32 bytes.
func MasterKeyFromBytes(raw []byte) (*MasterKey, error) {
	if len(raw) != masterKeyLen {
		return nil, ErrInvalidKey
	}
	var m MasterKey
	copy(m.secret[:], raw)
	if isAllZero(m.secret[:]) {
		return nil, ErrInvalidKey
	}
	return &m, nil
}

// Bytes returns the canonical 32-byte encoding of the master key.
func (m *MasterKey) Bytes() []byte {
	out := make([]byte, masterKeyLen)
	copy(out, m.secret[:])
	return out
}

// ReceiverKeys is the deterministic key bundle derived from a master key.
type ReceiverKeys struct {
	SpendPrivate []byte
	ViewPrivate  []byte
	SpendPublic  []byte
	ViewPublic   []byte
}

// DeriveReceiverKeys deterministically derives independent spend and view
// key pairs from the master key.
func DeriveReceiverKeys(master *MasterKey) (*ReceiverKeys, error) {
	if master == nil {
		return nil, ErrInvalidKey
	}
	spendPrivate, err := deriveScalar(master.secret[:], spendDerivationDomain)
	if err != nil {
		return nil, err
	}
	viewPrivate, err := deriveScalar(master.secret[:], viewDerivationDomain)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	spendX, spendY := curve.ScalarBaseMult(spendPrivate)
	viewX, viewY := curve.ScalarBaseMult(viewPrivate)
	return &ReceiverKeys{
		SpendPrivate: cloneBytes(spendPrivate),
		ViewPrivate:  cloneBytes(viewPrivate),
		SpendPublic:  elliptic.MarshalCompressed(curve, spendX, spendY),
		ViewPublic:   elliptic.MarshalCompressed(curve, viewX, viewY),
	}, nil
}

// deriveScalar derives a canonical P-256 private scalar in [1, N-1] from the
// master secret. The counter makes rejection sampling deterministic for the
// astronomically unlikely case that an expanded value is zero or >= N.
func deriveScalar(master []byte, domain string) ([]byte, error) {
	curve := elliptic.P256()
	for counter := uint32(0); ; counter++ {
		var info [8 + 4]byte
		copy(info[:], domain)
		binary.BigEndian.PutUint32(info[len(domain):], counter)
		raw, err := hkdf.Key(sha256.New, master, []byte(hkdfSalt), string(info[:len(domain)+4]), masterKeyLen)
		if err != nil {
			return nil, err
		}
		d := new(big.Int).SetBytes(raw)
		if d.Sign() > 0 && d.Cmp(curve.Params().N) < 0 {
			return raw, nil
		}
	}
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
