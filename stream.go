package stealth

import (
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// frame layout on disk:
//
//	[2 bytes magic 0x53 0x4f][4 bytes big-endian payload length]
//	[payload (JSON-encoded framePayload)]
//	[4 bytes big-endian CRC32-IEEE of payload]
//
// The log is append-only and fsynced per record. On open, any partially
// written or checksum-bad tail is truncated, so partial writes are never
// observed as records.
const (
	streamFileName = "outputs.log"
	streamMetaName = "outputs.meta"
	frameMagic0    = byte(0x53)
	frameMagic1    = byte(0x4f)
)

type framePayload struct {
	Seq          uint64 `json:"seq"`
	ID           []byte `json:"id"`
	EphemeralPub []byte `json:"r"`
	OneTimePub   []byte `json:"p"`
	Amount       uint64 `json:"amount"`
	Meta         []byte `json:"meta,omitempty"`
}

type indexedOutput struct {
	seq uint64
	rec *OutputRecord
	off int64
}

type outputStream struct {
	mu      sync.Mutex
	f       *os.File
	path    string
	records []*indexedOutput
	byID    map[string]uint64
	nextSeq uint64
	// retainedFirst is the smallest sequence number that has not been
	// pruned. It is 1 until the first successful prune.
	retainedFirst uint64
}

func openOutputStream(dir string) (*outputStream, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	st := &outputStream{
		path:          filepath.Join(dir, streamFileName),
		byID:          make(map[string]uint64),
		nextSeq:       1,
		retainedFirst: 1,
	}
	if err := st.recover(); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *outputStream) metaPath() string {
	return filepath.Join(filepath.Dir(st.path), streamMetaName)
}

func (st *outputStream) loadMeta() error {
	data, err := os.ReadFile(st.metaPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) != 8 {
		return ErrCorruptStorage
	}
	v := binary.BigEndian.Uint64(data)
	if v > st.retainedFirst {
		st.retainedFirst = v
	}
	return nil
}

func (st *outputStream) storeMeta() error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, st.retainedFirst)
	tmp := st.metaPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, st.metaPath()); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(st.metaPath()))
}

func (st *outputStream) close() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.f == nil {
		return nil
	}
	err := st.f.Close()
	st.f = nil
	return err
}

// recover replays the whole log, building the index and truncating any
// invalid tail.
func (st *outputStream) recover() error {
	f, err := os.OpenFile(st.path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	st.f = f

	var validEnd int64
	r := io.NewSectionReader(f, 0, 1<<63-1)
	var off int64
	var maxSeq uint64

	hdr := make([]byte, 6)
	for {
		n, err := io.ReadFull(r, hdr)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			if n == 0 {
				validEnd = off
				break
			}
			break
		}
		if err != nil {
			return err
		}
		if hdr[0] != frameMagic0 || hdr[1] != frameMagic1 {
			return ErrCorruptStorage
		}
		plen := int(binary.BigEndian.Uint32(hdr[2:6]))
		if plen <= 0 || plen > 1<<20 {
			return ErrCorruptStorage
		}

		payload := make([]byte, plen)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		crcBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, crcBuf); err != nil {
			break
		}
		if binary.BigEndian.Uint32(crcBuf) != crc32.ChecksumIEEE(payload) {
			break
		}

		var fp framePayload
		if err := json.Unmarshal(payload, &fp); err != nil {
			break
		}
		rec := fp.record()
		frameLen := int64(6 + plen + 4)
		st.records = append(st.records, &indexedOutput{
			seq: fp.Seq,
			rec: rec,
			off: off,
		})
		if e := st.records[len(st.records)-1]; e.seq > maxSeq {
			maxSeq = e.seq
		}
		if len(rec.ID) > 0 {
			if _, exists := st.byID[string(rec.ID)]; !exists {
				st.byID[string(rec.ID)] = fp.Seq
			}
		}
		off += frameLen
		validEnd = off
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != validEnd {
		// A partial/corrupt tail existed; remove it atomically w.r.t. readers
		// because append holds the same lock.
		if err := f.Truncate(validEnd); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	st.nextSeq = maxSeq + 1
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return st.loadMeta()
}

// append durably appends rec and returns its sequence number. A duplicate
// ID returns the existing sequence with ok=false (no new record written).
func (st *outputStream) append(rec *OutputRecord) (seq uint64, ok bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if len(rec.ID) > 0 {
		if existing, dup := st.byID[string(rec.ID)]; dup {
			return existing, false, nil
		}
	}

	fp := framePayload{
		Seq:          st.nextSeq,
		ID:           cloneBytes(rec.ID),
		EphemeralPub: cloneBytes(rec.EphemeralPub),
		OneTimePub:   cloneBytes(rec.OneTimePub),
		Amount:       rec.Amount,
		Meta:         cloneBytes(rec.Meta),
	}
	payload, err := json.Marshal(&fp)
	if err != nil {
		return 0, false, err
	}

	frame := make([]byte, 0, 6+len(payload)+4)
	frame = append(frame, frameMagic0, frameMagic1)
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(payload)))
	frame = append(frame, sizeBuf...)
	frame = append(frame, payload...)
	crcBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBuf, crc32.ChecksumIEEE(payload))
	frame = append(frame, crcBuf...)

	off, err := st.f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, false, err
	}
	n, err := st.f.Write(frame)
	if err != nil {
		return 0, false, err
	}
	if n != len(frame) {
		return 0, false, io.ErrShortWrite
	}
	if err := st.f.Sync(); err != nil {
		return 0, false, err
	}

	seq = st.nextSeq
	st.records = append(st.records, &indexedOutput{
		seq: seq,
		rec: cloneRecord(rec),
		off: off,
	})
	if len(rec.ID) > 0 {
		st.byID[string(rec.ID)] = seq
	}
	st.nextSeq++
	return seq, true, nil
}

// retainedSeq returns the sequence number of the first retained record and
// the frontier (nextSeq). Seq values below retained have been pruned.
func (st *outputStream) retainedSeq() (first, frontier uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.retainedFirst, st.nextSeq
}

// snapshot returns a point-in-time copy of all retained records together
// with the frontier at which the copy was taken.
func (st *outputStream) snapshot() ([]*indexedOutput, uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	snap := make([]*indexedOutput, len(st.records))
	copy(snap, st.records)
	return snap, st.nextSeq
}

// frontierSeq is one past the last sequence number present; it is also the
// sequence number that the next appended record will receive.
func (st *outputStream) frontierSeq() uint64 {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.nextSeq
}

func (st *outputStream) lastSeq() uint64 {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.records) == 0 {
		return 0
	}
	return st.records[len(st.records)-1].seq
}

func (st *outputStream) findID(id []byte) (seq uint64, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	seq, ok = st.byID[string(id)]
	return seq, ok
}

func (st *outputStream) recordAt(seq uint64) (*OutputRecord, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, e := range st.records {
		if e.seq == seq {
			return e.rec, true
		}
	}
	return nil, false
}

// pruneBefore atomically removes every record with seq < beforeSeq and
// writes a replacement log, then renames it over the old one.
func (st *outputStream) pruneBefore(beforeSeq uint64) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	tmpPath := st.path + ".tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	var kept []*indexedOutput
	for _, e := range st.records {
		if e.seq < beforeSeq {
			continue
		}
		frame, err := encodeFrame(e.seq, e.rec)
		if err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return err
		}
		if _, err := tmp.Write(frame); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return err
		}
		kept = append(kept, e)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Commit the new retention boundary before replacing the log. If a
	// crash happens between the two atomic steps, the boundary may be
	// advanced while the old data is still present (a conservative state:
	// scans that would skip history still get ErrPrunedData); the reverse
	// order could silently drop history under cursors behind the boundary.
	newRetained := beforeSeq
	if newRetained > st.nextSeq {
		newRetained = st.nextSeq
	}
	if newRetained > st.retainedFirst {
		prev := st.retainedFirst
		st.retainedFirst = newRetained
		if err := st.storeMeta(); err != nil {
			st.retainedFirst = prev
			os.Remove(tmpPath)
			return err
		}
	}

	if err := os.Rename(tmpPath, st.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := syncDir(filepath.Dir(st.path)); err != nil {
		return err
	}

	f, err := os.OpenFile(st.path, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	if st.f != nil {
		st.f.Close()
	}
	st.f = f
	st.records = kept
	// Rebuild ID index for retained records.
	st.byID = make(map[string]uint64)
	for _, e := range kept {
		if len(e.rec.ID) > 0 {
			if _, exists := st.byID[string(e.rec.ID)]; !exists {
				st.byID[string(e.rec.ID)] = e.seq
			}
		}
	}
	return nil
}

func encodeFrame(seq uint64, rec *OutputRecord) ([]byte, error) {
	fp := framePayload{
		Seq:          seq,
		ID:           rec.ID,
		EphemeralPub: rec.EphemeralPub,
		OneTimePub:   rec.OneTimePub,
		Amount:       rec.Amount,
		Meta:         rec.Meta,
	}
	payload, err := json.Marshal(&fp)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 0, 6+len(payload)+4)
	frame = append(frame, frameMagic0, frameMagic1)
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(payload)))
	frame = append(frame, sizeBuf...)
	frame = append(frame, payload...)
	crcBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBuf, crc32.ChecksumIEEE(payload))
	frame = append(frame, crcBuf...)
	return frame, nil
}

func (fp framePayload) record() *OutputRecord {
	return &OutputRecord{
		ID:           cloneBytes(fp.ID),
		EphemeralPub: cloneBytes(fp.EphemeralPub),
		OneTimePub:   cloneBytes(fp.OneTimePub),
		Amount:       fp.Amount,
		Meta:         cloneBytes(fp.Meta),
	}
}

func cloneRecord(rec *OutputRecord) *OutputRecord {
	return &OutputRecord{
		ID:           cloneBytes(rec.ID),
		EphemeralPub: cloneBytes(rec.EphemeralPub),
		OneTimePub:   cloneBytes(rec.OneTimePub),
		Amount:       rec.Amount,
		Meta:         cloneBytes(rec.Meta),
	}
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
