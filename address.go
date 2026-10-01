package stealth

import (
	"crypto/sha256"
	"io"
	"math/big"
)

// StealthAddress is a one-time payment address published in the output
// stream. EphemeralPub is the sender ephemeral public key R; OneTimePub is
// the one-time output public key P.
//
// Protocol (dual-key stealth addresses over P-256):
//
//	Sender, receiver scan pubkey V and spend pubkey B:
//	  r            <- random scalar
//	  R            = r*G
//	  h            = H(domain, R, r*V)
//	  P            = B + h*G
//
//	Receiver scanning with view key v (V = v*G):
//	  h            = H(domain, R, v*R)
//	  output owned iff P == B + h*G
//
//	Receiver spending:
//	  p            = b + h  (mod N), where b is the spend private key.
type StealthAddress struct {
	EphemeralPub []byte
	OneTimePub   []byte
}

// outputHash derives h = H(domain, R, shared) from the sender ephemeral
// point R and a shared point.
func outputHash(rx, ry *big.Int, sharedX, sharedY *big.Int) *big.Int {
	r := marshalPoint(rx, ry)
	s := marshalPoint(sharedX, sharedY)
	return hashToScalar(domainOutput, r, s)
}

// matchOutput reports whether the one-time point px,py equals
// B + H(domain, R, v*R)*G for the given scan private scalar and spend point.
func matchOutput(scanPriv *big.Int, bx, by *big.Int, rx, ry, px, py *big.Int) (*big.Int, bool) {
	sx, sy := pointMult(scanPriv, rx, ry)
	h := outputHash(rx, ry, sx, sy)
	hx, hy := baseMult(h)
	tx, ty := pointAdd(bx, by, hx, hy)
	return h, tx.Cmp(px) == 0 && ty.Cmp(py) == 0
}

// senderShared computes r*V from the sender ephemeral scalar and scan point.
func senderShared(r *big.Int, vx, vy *big.Int) (x, y *big.Int) {
	return pointMult(r, vx, vy)
}

// GenerateStealthAddress creates a fresh one-time address for the holder of
// the given public key set, drawing ephemeral randomness from rand.
func GenerateStealthAddress(pub *PublicKeySet, rand io.Reader) (*StealthAddress, error) {
	if pub == nil {
		return nil, ErrInvalidArgument
	}
	vx, vy, ok := parsePoint(pub.ScanPub)
	if !ok {
		return nil, ErrInvalidAddress
	}
	bx, by, ok := parsePoint(pub.SpendPub)
	if !ok {
		return nil, ErrInvalidAddress
	}

	r, err := randScalar(rand)
	if err != nil {
		return nil, err
	}
	rx, ry := baseMult(r)

	sx, sy := senderShared(r, vx, vy)
	h := outputHash(rx, ry, sx, sy)
	hx, hy := baseMult(h)
	px, py := pointAdd(bx, by, hx, hy)

	return &StealthAddress{
		EphemeralPub: marshalPoint(rx, ry),
		OneTimePub:   marshalPoint(px, py),
	}, nil
}

// ParseStealthAddress validates and parses an on-the-wire address.
func ParseStealthAddress(ephemeralPub, oneTimePub []byte) (*StealthAddress, error) {
	if _, _, ok := parsePoint(ephemeralPub); !ok {
		return nil, ErrInvalidAddress
	}
	if _, _, ok := parsePoint(oneTimePub); !ok {
		return nil, ErrInvalidAddress
	}
	return &StealthAddress{
		EphemeralPub: cloneBytes(ephemeralPub),
		OneTimePub:   cloneBytes(oneTimePub),
	}, nil
}

// EncodeStealthAddress returns a canonical textual encoding of the address:
// the hex SHA-256(R || P) digest. It is a content-addressed label, not an
// address that can be spent from on its own.
func EncodeStealthAddress(addr *StealthAddress) string {
	h := sha256.New()
	h.Write(addr.EphemeralPub)
	h.Write(addr.OneTimePub)
	return encodeHex(h.Sum(nil))
}

var hexAlphabet = []byte("0123456789abcdef")

func encodeHex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexAlphabet[c>>4]
		out[i*2+1] = hexAlphabet[c&0x0f]
	}
	return string(out)
}
