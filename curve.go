package stealth

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
)

// All key material uses NIST P-256, provided by the Go standard library.
// Points are exchanged in the 33-byte compressed SEC1 form.

var p256 = elliptic.P256()

func curveOrder() *big.Int {
	return new(big.Int).Set(p256.Params().N)
}

// randScalar draws a uniformly random scalar in [1, N-1] from r.
func randScalar(r io.Reader) (*big.Int, error) {
	n := curveOrder()
	for {
		k, err := rand.Int(r, new(big.Int).Sub(n, big.NewInt(2)))
		if err != nil {
			return nil, err
		}
		k.Add(k, big.NewInt(1))
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

// hashToScalar derives a nonzero scalar from a domain-separated SHA-256
// hash of the concatenated inputs.
func hashToScalar(domain string, parts ...[]byte) *big.Int {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write(p)
	}
	sum := h.Sum(nil)
	k := new(big.Int).SetBytes(sum)
	k.Mod(k, curveOrder())
	if k.Sign() == 0 {
		k.SetInt64(1)
	}
	return k
}

func scalarBytes(k *big.Int) Scalar {
	var out Scalar
	b := k.Bytes()
	copy(out[32-len(b):], b)
	return out
}

func scalarFromBytes(b []byte) (*big.Int, bool) {
	if len(b) != 32 {
		return nil, false
	}
	k := new(big.Int).SetBytes(b)
	n := curveOrder()
	if k.Sign() == 0 || k.Cmp(n) >= 0 {
		return nil, false
	}
	return k, true
}

func baseMult(k *big.Int) (x, y *big.Int) {
	return p256.ScalarBaseMult(k.Bytes())
}

func pointMult(k *big.Int, px, py *big.Int) (x, y *big.Int) {
	return p256.ScalarMult(px, py, k.Bytes())
}

func pointAdd(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	return p256.Add(x1, y1, x2, y2)
}

func marshalPoint(x, y *big.Int) []byte {
	return elliptic.MarshalCompressed(p256, x, y)
}

func parsePoint(b []byte) (x, y *big.Int, ok bool) {
	x, y = elliptic.UnmarshalCompressed(p256, b)
	if x == nil {
		return nil, nil, false
	}
	return x, y, true
}

func randomReader() io.Reader {
	return rand.Reader
}
