package stealth

// OutputRecord is an external submission placed into the local output
// stream. ID uniquely identifies an output; duplicate submissions with the
// same ID are treated as idempotent re-deliveries.
type OutputRecord struct {
	ID           []byte
	EphemeralPub []byte
	OneTimePub   []byte
	Amount       uint64
	Meta         []byte
}
