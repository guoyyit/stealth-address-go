package stealth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const registryFileName = "registry.json"

type registryEntry struct {
	ScanPub  []byte `json:"scan_pub"`
	SpendPub []byte `json:"spend_pub"`
}

type registry struct {
	mu      sync.RWMutex
	path    string
	entries map[string]registryEntry
}

func openRegistry(dir string) (*registry, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	r := &registry{
		path:    filepath.Join(dir, registryFileName),
		entries: make(map[string]registryEntry),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *registry) close() error {
	return nil
}

func (r *registry) load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &r.entries); err != nil {
		return ErrCorruptStorage
	}
	return nil
}

// persist writes the full snapshot atomically: temp file, fsync, rename,
// fsync directory. Partial registry writes can therefore never be observed.
func (r *registry) persistLocked() error {
	data, err := json.MarshalIndent(&r.entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
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
	if err := os.Rename(tmp, r.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(r.path))
}

func (r *registry) put(id string, pub *PublicKeySet) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[id]; exists {
		return false, nil
	}
	r.entries[id] = registryEntry{
		ScanPub:  cloneBytes(pub.ScanPub),
		SpendPub: cloneBytes(pub.SpendPub),
	}
	if err := r.persistLocked(); err != nil {
		delete(r.entries, id)
		return false, err
	}
	return true, nil
}

func (r *registry) remove(id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[id]; !exists {
		return false, nil
	}
	prev := r.entries[id]
	delete(r.entries, id)
	if err := r.persistLocked(); err != nil {
		r.entries[id] = prev
		return false, err
	}
	return true, nil
}

func (r *registry) get(id string) (*PublicKeySet, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	if !ok {
		return nil, false
	}
	return &PublicKeySet{ScanPub: cloneBytes(e.ScanPub), SpendPub: cloneBytes(e.SpendPub)}, true
}

func (r *registry) list() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
