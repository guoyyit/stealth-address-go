package stealth

import "errors"

// Output is a record in the local output stream. It contains only public
// stealth-address material: the ephemeral public key R and the one-time
// public key P. It deliberately carries no receiver identity.
type Output struct {
	// Sequence is the 1-based position assigned by the local output stream.
	Sequence uint64
	// EphemeralPublic is the sender ephemeral public key R (compressed P-256 point).
	EphemeralPublic []byte
	// OneTimePublic is the one-time payment public key P (compressed P-256 point).
	OneTimePublic []byte
}

// OutputID is the canonical identity of an output, derived solely from its
// public cryptographic material. Submitting the same material twice yields
// the same ID and is de-duplicated.
type OutputID [32]byte

// Sentinel errors. Failure causes are distinguishable so callers never have
// to guess why an operation (in particular key recovery) failed.
var (
	ErrNotImplemented    = errors.New("stealth: not implemented")
	ErrInvalidKey        = errors.New("stealth: invalid key")
	ErrUnknownReceiver   = errors.New("stealth: unknown receiver")
	ErrReceiverExists    = errors.New("stealth: receiver already registered")
	ErrReceiverRevoked   = errors.New("stealth: receiver revoked")
	ErrInvalidViewKey    = errors.New("stealth: invalid view key")
	ErrInvalidSpendKey   = errors.New("stealth: invalid spend key")
	ErrNotOwnOutput      = errors.New("stealth: output does not belong to receiver")
	ErrOutputNotFound    = errors.New("stealth: output not found")
	ErrOutputPruned      = errors.New("stealth: output pruned, recovery material unavailable")
	ErrInvalidOutput     = errors.New("stealth: invalid output record")
	ErrInvalidCheckpoint = errors.New("stealth: invalid acknowledgement checkpoint")
)
