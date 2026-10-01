package stealth

import (
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"io"
	"math/big"
)

const (
	// privateScalarLen is the canonical big-endian length of a P-256 scalar.
	privateScalarLen = 32

	// compressedPointLen is the length of a compressed P-256 point.
	compressedPointLen = 33

	// sharedDerivationDomain separates the one-time-address hash from all
	// other key derivation uses.
	sharedDerivationDomain = "otv"
)

var p256Curve = elliptic.P256()

// OneTimeAddress is a single-use payment address generated for a receiver.
type OneTimeAddress struct {
	// EphemeralPublic is R, published alongside the output.
	EphemeralPublic []byte
	// OneTimePublic is P, the actual payment destination.
	OneTimePublic []byte
}

// CreateOneTimeAddress generates a fresh unlinkable one-time address from the
// receiver public spend key S and public view key V.
func CreateOneTimeAddress(rng io.Reader, spendPublic, viewPublic []byte) (*OneTimeAddress, error) {
	spendX, spendY := elliptic.UnmarshalCompressed(p256Curve, spendPublic)
	if spendX == nil {
		return nil, ErrInvalidKey
	}
	viewX, viewY := elliptic.UnmarshalCompressed(p256Curve, viewPublic)
	if viewX == nil {
		return nil, ErrInvalidKey
	}

	ephemeralScalar := make([]byte, privateScalarLen)
	if rng == nil {
		return nil, ErrInvalidKey
	}
	if _, err := io.ReadFull(rng, ephemeralScalar); err != nil {
		return nil, err
	}

	ephemeralX, ephemeralY := p256Curve.ScalarBaseMult(ephemeralScalar)
	if ephemeralX == nil {
		return nil, ErrInvalidKey
	}

	sharedX, _ := p256Curve.ScalarMult(viewX, viewY, ephemeralScalar)
	c, err := sharedSecretScalar(sharedX)
	if err != nil {
		return nil, err
	}
	cGX, cGY := p256Curve.ScalarBaseMult(canonicalScalar(c))
	oneTimeX, oneTimeY := p256Curve.Add(spendX, spendY, cGX, cGY)

	return &OneTimeAddress{
		EphemeralPublic: elliptic.MarshalCompressed(p256Curve, ephemeralX, ephemeralY),
		OneTimePublic:   elliptic.MarshalCompressed(p256Curve, oneTimeX, oneTimeY),
	}, nil
}

// OutputIDFor computes the canonical identity of an output.
func OutputIDFor(ephemeralPublic, oneTimePublic []byte) (OutputID, error) {
	if len(ephemeralPublic) == 0 || len(oneTimePublic) == 0 {
		return OutputID{}, ErrInvalidOutput
	}
	h := sha256.New()
	h.Write([]byte(hkdfSalt))
	h.Write([]byte("/output-id"))
	var length [8]byte
	length[7] = byte(len(ephemeralPublic))
	h.Write(length[:])
	h.Write(ephemeralPublic)
	length[7] = byte(len(oneTimePublic))
	h.Write(length[:])
	h.Write(oneTimePublic)
	var id OutputID
	copy(id[:], h.Sum(nil))
	return id, nil
}

// BelongsTo reports whether the output belongs to the holder of viewPrivate,
// given the receiver public spend key. It needs no spend capability.
func BelongsTo(viewPrivate, spendPublic []byte, out *Output) (bool, error) {
	if out == nil {
		return false, ErrInvalidOutput
	}
	expectedOneTime, err := oneTimeForOutput(viewPrivate, spendPublic, out.EphemeralPublic)
	if err != nil {
		return false, err
	}
	return bytesEqual(expectedOneTime, out.OneTimePublic), nil
}

// RecoverOneTimeKey recovers the one-time private key for an owned output.
// It requires both the spend secret and the view secret.
func RecoverOneTimeKey(spendPrivate, viewPrivate []byte, out *Output) ([]byte, error) {
	if out == nil {
		return nil, ErrInvalidOutput
	}
	spendScalar, ok := validPrivateScalar(spendPrivate)
	if !ok {
		return nil, ErrInvalidSpendKey
	}
	ephemeralX, ephemeralY := elliptic.UnmarshalCompressed(p256Curve, out.EphemeralPublic)
	if ephemeralX == nil {
		return nil, ErrInvalidOutput
	}
	claimedX, claimedY := elliptic.UnmarshalCompressed(p256Curve, out.OneTimePublic)
	if claimedX == nil {
		return nil, ErrInvalidOutput
	}
	sharedX, _ := p256Curve.ScalarMult(ephemeralX, ephemeralY, viewPrivate)
	c, err := sharedSecretScalar(sharedX)
	if err != nil {
		return nil, err
	}
	oneTimeScalar := new(big.Int).Add(spendScalar, c)
	oneTimeScalar.Mod(oneTimeScalar, p256Curve.Params().N)
	if oneTimeScalar.Sign() == 0 {
		return nil, ErrNotOwnOutput
	}

	gotX, gotY := p256Curve.ScalarBaseMult(canonicalScalar(oneTimeScalar))
	if gotX.Cmp(claimedX) != 0 || gotY.Cmp(claimedY) != 0 {
		return nil, ErrNotOwnOutput
	}
	return canonicalScalar(oneTimeScalar), nil
}

// oneTimeForOutput recomputes the expected one-time public key P = S + c*G
// from the view secret and an ephemeral public key R.
func oneTimeForOutput(viewPrivate, spendPublic, ephemeralPublic []byte) ([]byte, error) {
	if _, ok := validPrivateScalar(viewPrivate); !ok {
		return nil, ErrInvalidViewKey
	}
	spendX, spendY := elliptic.UnmarshalCompressed(p256Curve, spendPublic)
	if spendX == nil {
		return nil, ErrInvalidKey
	}
	ephemeralX, ephemeralY := elliptic.UnmarshalCompressed(p256Curve, ephemeralPublic)
	if ephemeralX == nil {
		return nil, ErrInvalidOutput
	}
	sharedX, _ := p256Curve.ScalarMult(ephemeralX, ephemeralY, viewPrivate)
	c, err := sharedSecretScalar(sharedX)
	if err != nil {
		return nil, err
	}
	cGX, cGY := p256Curve.ScalarBaseMult(canonicalScalar(c))
	oneTimeX, oneTimeY := p256Curve.Add(spendX, spendY, cGX, cGY)
	return elliptic.MarshalCompressed(p256Curve, oneTimeX, oneTimeY), nil
}

// sharedSecretScalar maps the x-coordinate of an ECDH shared point to a
// P-256 scalar c via HKDF-SHA256.
func sharedSecretScalar(sharedX *big.Int) (*big.Int, error) {
	raw, err := hkdf.Key(sha256.New, canonicalCoord(sharedX), []byte(hkdfSalt), sharedDerivationDomain, privateScalarLen)
	if err != nil {
		return nil, err
	}
	c := new(big.Int).SetBytes(raw)
	c.Mod(c, p256Curve.Params().N)
	return c, nil
}

// validPrivateScalar parses a canonical P-256 private scalar in [1, N-1].
func validPrivateScalar(raw []byte) (*big.Int, bool) {
	if len(raw) != privateScalarLen {
		return nil, false
	}
	d := new(big.Int).SetBytes(raw)
	if d.Sign() == 0 || d.Cmp(p256Curve.Params().N) >= 0 {
		return nil, false
	}
	return d, true
}

func canonicalScalar(d *big.Int) []byte {
	out := make([]byte, privateScalarLen)
	d.FillBytes(out)
	return out
}

func canonicalCoord(x *big.Int) []byte {
	out := make([]byte, p256Curve.Params().P.BitLen()/8)
	x.FillBytes(out)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
