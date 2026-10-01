package stealth

import "math/big"

// RecoverOneTimePrivateKey derives the one-time private key p = b + h
// (mod N) for an address, where h = H(domain, R, v*R) is recomputed from
// the receiver's scan private key v.
//
// The function fails with distinguishable errors:
//   - ErrInvalidAddress: malformed points;
//   - ErrViewKeyMismatch: the provided scan/spend keys are not a coherent
//     pair for the address (the address does not belong to this receiver);
//   - ErrInvalidArgument: kp is nil.
func RecoverOneTimePrivateKey(kp *KeyPair, ephemeralPub, oneTimePub []byte) (Scalar, error) {
	var zero Scalar
	if kp == nil {
		return zero, ErrInvalidArgument
	}
	v, ok := scalarValue(kp.ScanPriv)
	if !ok {
		return zero, ErrInvalidArgument
	}
	b, ok := scalarValue(kp.SpendPriv)
	if !ok {
		return zero, ErrInvalidArgument
	}
	rx, ry, ok := parsePoint(ephemeralPub)
	if !ok {
		return zero, ErrInvalidAddress
	}
	px, py, ok := parsePoint(oneTimePub)
	if !ok {
		return zero, ErrInvalidAddress
	}
	bx, by, ok := parsePoint(kp.SpendPub)
	if !ok {
		return zero, ErrInvalidAddress
	}

	h, owned := matchOutput(v, bx, by, rx, ry, px, py)
	if !owned {
		return zero, ErrNotOwner
	}

	// Defense in depth: the spend public key must correspond to b.
	checkX, checkY := baseMult(b)
	if checkX.Cmp(bx) != 0 || checkY.Cmp(by) != 0 {
		return zero, ErrViewKeyMismatch
	}

	p := new(big.Int).Add(b, h)
	p.Mod(p, curveOrder())
	return scalarBytes(p), nil
}
