package stealth

import "io"

// Service is a one-time payment address service. It persists externally
// submitted outputs as a local output stream, lets senders generate unlinkable
// one-time addresses for registered receivers, lets receivers scan the stream
// with a read-only view key and recover one-time private keys with the spend key.
type Service struct{}

// OpenService opens a service whose state lives in dir.
func OpenService(dir string) (*Service, error) {
	return nil, ErrNotImplemented
}

// Close flushes and releases all on-disk state.
func (s *Service) Close() error {
	return ErrNotImplemented
}

// Register records a receiver identity with its public spend and view keys.
func (s *Service) Register(receiverID string, spendPublic, viewPublic []byte) error {
	return ErrNotImplemented
}

// Revoke marks a receiver revoked so no new one-time addresses can be generated.
func (s *Service) Revoke(receiverID string) error {
	return ErrNotImplemented
}

// GenerateAddress creates a fresh unlinkable one-time address for a receiver.
func (s *Service) GenerateAddress(receiverID string, rng io.Reader) (*OneTimeAddress, error) {
	return nil, ErrNotImplemented
}

// SubmitOutput appends an externally produced output record to the stream.
// Duplicate material is de-duplicated to the existing output.
func (s *Service) SubmitOutput(ephemeralPublic, oneTimePublic []byte) (OutputID, error) {
	return OutputID{}, ErrNotImplemented
}

// Scan incorporates new stream outputs into the receiver's durable progress
// and returns the outputs discovered but not yet acknowledged.
func (s *Service) Scan(receiverID string, viewPrivate []byte) ([]Output, error) {
	return nil, ErrNotImplemented
}

// Acknowledge marks the delivered outputs up to and including last as delivered.
func (s *Service) Acknowledge(receiverID string, viewPrivate []byte, last OutputID) error {
	return ErrNotImplemented
}

// Recover returns the one-time private key for a discovered owned output.
func (s *Service) Recover(receiverID string, spendPrivate, viewPrivate []byte, id OutputID) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Prune removes stream outputs with sequence strictly below beforeSequence.
// It returns the number of records removed.
func (s *Service) Prune(beforeSequence uint64) (int, error) {
	return 0, ErrNotImplemented
}

// Rescan discards the receiver scan progress and replays the retained stream.
func (s *Service) Rescan(receiverID string, viewPrivate []byte) ([]Output, error) {
	return nil, ErrNotImplemented
}
