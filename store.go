package stealth

// diskStore persists the registry, the append-only output stream and per
// receiver scan progress, all with atomic durable writes.
type diskStore struct {
	dir string
}

// openStore opens (or creates) the on-disk state in dir and replays it.
func openStore(dir string) (*diskStore, error) {
	return nil, ErrNotImplemented
}

func (s *diskStore) close() error {
	return ErrNotImplemented
}
