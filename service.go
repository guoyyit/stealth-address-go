package stealth

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrReceiverNotFound = errors.New("stealth: receiver not registered")
	ErrReceiverExists   = errors.New("stealth: receiver already registered")
	ErrInvalidArgument  = errors.New("stealth: invalid argument")
	ErrInvalidAddress   = errors.New("stealth: invalid stealth address")
	ErrViewKeyMismatch  = errors.New("stealth: view/scan key does not match receiver")
	ErrSpendKeyMismatch = errors.New("stealth: spend key does not match receiver")
	ErrNotOwner         = errors.New("stealth: output does not belong to receiver")
	ErrPrunedData       = errors.New("stealth: required historical outputs have been pruned")
	ErrCorruptStorage   = errors.New("stealth: corrupt storage")
	ErrOutputExists     = errors.New("stealth: output id already exists")
	ErrOutputNotFound   = errors.New("stealth: output not found")
)

// Config configures an on-disk Service.
type Config struct {
	Dir string
}

// MatchedOutput is an output discovered during a scan.
type MatchedOutput struct {
	Seq    uint64
	Record *OutputRecord
}

// ScanReport is the deterministic result of a Scan or Rescan call.
type ScanReport struct {
	// Outputs are the receiver's outputs in ascending stream order, with
	// duplicates (by output ID) suppressed.
	Outputs []*MatchedOutput
	// Cursor is the scan cursor atomically committed by this call.
	Cursor uint64
}

// Service is a one-time stealth-address receiving service backed by a local
// directory.
//
// A single Service is safe for concurrent use. Scans for a given receiver
// are serialized so that concurrent scanners never double-report committed
// ranges; different receivers scan independently.
type Service struct {
	dir      string
	stream   *outputStream
	registry *registry

	scanMu sync.Mutex
	scans  map[string]*scanLock
}

type scanLock struct {
	mu sync.Mutex
}

// Open opens (or creates) a persistent service in cfg.Dir.
func Open(cfg Config) (*Service, error) {
	if cfg.Dir == "" {
		return nil, ErrInvalidArgument
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, err
	}
	stream, err := openOutputStream(cfg.Dir)
	if err != nil {
		return nil, err
	}
	reg, err := openRegistry(cfg.Dir)
	if err != nil {
		stream.close()
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(cfg.Dir, "scans"), 0o755); err != nil {
		stream.close()
		return nil, err
	}
	return &Service{
		dir:      cfg.Dir,
		stream:   stream,
		registry: reg,
		scans:    make(map[string]*scanLock),
	}, nil
}

// Close flushes and releases all on-disk resources.
func (s *Service) Close() error {
	s.scanMu.Lock()
	for _, l := range s.scans {
		l.mu.Lock()
		l.mu.Unlock()
	}
	s.scanMu.Unlock()

	err1 := s.registry.close()
	err2 := s.stream.close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *Service) lockScan(id string) *scanLock {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	l, ok := s.scans[id]
	if !ok {
		l = &scanLock{}
		s.scans[id] = l
	}
	return l
}

// RegisterReceiver registers a receiver's public key set under id, derived
// from the receiver's master key. Private key material is never stored.
func (s *Service) RegisterReceiver(id string, kp *KeyPair) error {
	if id == "" || kp == nil {
		return ErrInvalidArgument
	}
	if _, _, ok := parsePoint(kp.ScanPub); !ok {
		return ErrInvalidAddress
	}
	if _, _, ok := parsePoint(kp.SpendPub); !ok {
		return ErrInvalidAddress
	}
	ok, err := s.registry.put(id, kp.PublicOnly())
	if err != nil {
		return err
	}
	if !ok {
		return ErrReceiverExists
	}
	return nil
}

// UnregisterReceiver removes a receiver registration and its scan progress.
// Scans that were already in progress complete against the keys they
// captured; later scans fail with ErrReceiverNotFound.
func (s *Service) UnregisterReceiver(id string) error {
	if id == "" {
		return ErrInvalidArgument
	}
	ok, err := s.registry.remove(id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrReceiverNotFound
	}
	// Wait for any in-progress scan/recovery for the id, then drop its
	// cursor. Registration churn cannot interleave with scan state writes.
	l := s.lockScan(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := openScanState(s.dir, id)
	if err == nil {
		err = st.remove()
	}
	if err != nil {
		return err
	}
	return nil
}

// GenerateAddress generates a fresh one-time address for a registered
// receiver. A fresh sender ephemeral is used every time, so addresses for
// the same receiver are mutually unlinkable and reveal no identity.
func (s *Service) GenerateAddress(receiverID string) (*StealthAddress, error) {
	pub, ok := s.registry.get(receiverID)
	if !ok {
		return nil, ErrReceiverNotFound
	}
	return GenerateStealthAddress(pub, randomReader())
}

// SubmitOutput appends an externally created output record to the stream.
// Submitting the same ID twice is idempotent: the first occurrence defines
// the record, later submissions are ignored (ErrOutputExists).
func (s *Service) SubmitOutput(rec OutputRecord) error {
	if len(rec.ID) == 0 {
		return ErrInvalidArgument
	}
	if _, err := ParseStealthAddress(rec.EphemeralPub, rec.OneTimePub); err != nil {
		return err
	}
	_, ok, err := s.stream.append(&rec)
	if err != nil {
		return err
	}
	if !ok {
		return ErrOutputExists
	}
	return nil
}

func verifyViewKey(pub *PublicKeySet, viewKey Scalar) (*big.Int, error) {
	v, ok := scalarValue(viewKey)
	if !ok {
		return nil, ErrInvalidArgument
	}
	x, y := baseMult(v)
	want := marshalPoint(x, y)
	if !equalBytes(want, pub.ScanPub) {
		return nil, ErrViewKeyMismatch
	}
	return v, nil
}

// Scan incrementally reports outputs belonging to receiverID that arrived
// since the receiver's committed scan cursor, and atomically advances the
// cursor to the stream frontier.
//
// Semantics:
//   - Outputs are reported in ascending sequence order; duplicate IDs are
//     reported at most once across the whole history.
//   - The cursor is committed atomically together with the scan result,
//     before Scan returns, so a crash before return leads to one rescan of
//     the same range (and a Rescan dedupes for the caller), while a crash
//     after commit never replays the range.
//   - If the committed cursor points into a range that has since been
//     pruned, Scan fails with ErrPrunedData; callers must explicitly
//     Rescan. No historical output is ever silently skipped.
func (s *Service) Scan(receiverID string, viewKey Scalar) (*ScanReport, error) {
	return s.scanRange(receiverID, viewKey, false)
}

// Rescan deterministically re-scans the entire available (non-pruned)
// stream for receiverID and re-reports every currently retained output
// owned by the receiver, then commits the cursor to the stream frontier.
// Previously reported outputs are returned again: callers must treat
// Rescan output as an authoritative replacement keyed by output ID, not as
// new discoveries. Pruned outputs cannot be re-reported.
func (s *Service) Rescan(receiverID string, viewKey Scalar) (*ScanReport, error) {
	return s.scanRange(receiverID, viewKey, true)
}

func (s *Service) scanRange(receiverID string, viewKey Scalar, rescan bool) (*ScanReport, error) {
	if receiverID == "" {
		return nil, ErrInvalidArgument
	}
	pub, ok := s.registry.get(receiverID)
	if !ok {
		return nil, ErrReceiverNotFound
	}
	v, err := verifyViewKey(pub, viewKey)
	if err != nil {
		return nil, err
	}

	l := s.lockScan(receiverID)
	l.mu.Lock()
	defer l.mu.Unlock()
	// Re-check registration inside the serialized section: an
	// unregistration that won the race removes the cursor, and a scan that
	// only captured the public set must not recreate cursor state for a
	// receiver that no longer exists.
	if _, ok := s.registry.get(receiverID); !ok {
		return nil, ErrReceiverNotFound
	}

	st, err := openScanState(s.dir, receiverID)
	if err != nil {
		return nil, err
	}
	cur, err := st.load()
	if err != nil {
		return nil, err
	}

	retained, _ := s.stream.retainedSeq()
	startSeq := cur.Seq
	if rescan {
		startSeq = retained
	} else if cur.Seq == 0 {
		// Never scanned: start at the first available record. Pruned
		// history is not "lost progress" for this receiver.
		startSeq = retained
	} else if cur.Seq < retained {
		return nil, ErrPrunedData
	}

	bx, by, ok := parsePoint(pub.SpendPub)
	if !ok {
		return nil, ErrInvalidAddress
	}

	report := &ScanReport{}
	seen := make(map[string]bool)
	snap, snapFrontier := s.stream.snapshot()
	for _, e := range snap {
		if e.seq < startSeq {
			continue
		}
		rx, ry, rok := parsePoint(e.rec.EphemeralPub)
		px, py, pok := parsePoint(e.rec.OneTimePub)
		if !rok || !pok {
			continue
		}
		if _, owned := matchOutput(v, bx, by, rx, ry, px, py); !owned {
			continue
		}
		idKey := string(e.rec.ID)
		if idKey != "" && seen[idKey] {
			continue
		}
		if idKey != "" {
			seen[idKey] = true
		}
		report.Outputs = append(report.Outputs, &MatchedOutput{
			Seq:    e.seq,
			Record: cloneRecord(e.rec),
		})
	}

	// Commit cursor before returning: concurrent scans are serialized by
	// l.mu, and this durable commit is the boundary for crash recovery.
	committed := scanCursor{Seq: snapFrontier}
	if rescan {
		if err := st.reset(committed); err != nil {
			return nil, err
		}
	} else if snapFrontier > cur.Seq {
		if err := st.commit(committed); err != nil {
			return nil, err
		}
	}
	report.Cursor = snapFrontier
	return report, nil
}

// Prune permanently removes every output with sequence number < beforeSeq.
// Sequence numbers are not reused. Scans with committed cursors below
// beforeSeq subsequently fail with ErrPrunedData instead of silently
// skipping history; Rescan starts at the new frontier.
func (s *Service) Prune(beforeSeq uint64) error {
	return s.stream.pruneBefore(beforeSeq)
}

// Recover returns the one-time private key of a stored output owned by the
// receiver authenticated by kp. It distinguishes:
//
//   - ErrReceiverNotFound: receiverID is not registered;
//   - ErrViewKeyMismatch: kp.ScanPriv is not the receiver's view key;
//   - ErrSpendKeyMismatch: kp.SpendPriv is not the receiver's spend key;
//   - ErrOutputNotFound: outputID is unknown or has been pruned;
//   - ErrNotOwner: the output is not owned by this receiver.
//
// Holding only the view key is never sufficient: the spend private key is
// required, and it is never present in scan state or registry.
func (s *Service) Recover(receiverID string, outputID []byte, kp *KeyPair) (Scalar, error) {
	var zero Scalar
	if receiverID == "" || len(outputID) == 0 || kp == nil {
		return zero, ErrInvalidArgument
	}
	pub, ok := s.registry.get(receiverID)
	if !ok {
		return zero, ErrReceiverNotFound
	}
	if _, err := verifyViewKey(pub, kp.ScanPriv); err != nil {
		return zero, err
	}
	spend, ok := scalarValue(kp.SpendPriv)
	if !ok {
		return zero, ErrInvalidArgument
	}
	sx, sy := baseMult(spend)
	spub := marshalPoint(sx, sy)
	if !equalBytes(spub, pub.SpendPub) {
		return zero, ErrSpendKeyMismatch
	}

	seq, ok := s.stream.findID(outputID)
	if !ok {
		return zero, ErrOutputNotFound
	}
	rec, ok := s.stream.recordAt(seq)
	if !ok {
		return zero, ErrOutputNotFound
	}
	return RecoverOneTimePrivateKey(kp, rec.EphemeralPub, rec.OneTimePub)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
