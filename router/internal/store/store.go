// Package store persists configuration (with revision history), audit log,
// events and device aliases for routerd.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"router/internal/config"
	"router/pkg/models"
)

// MaxRevisions is how many configuration revisions are retained.
const MaxRevisions = 64

// EventRingSize is the in-memory event buffer bound.
const EventRingSize = 1024

// RevMeta describes a configuration revision.
type RevMeta struct {
	Rev     int       `json:"rev"`
	Time    time.Time `json:"time"`
	Author  string    `json:"author"`
	Message string    `json:"message"`
}

// AuditEntry is a security-sensitive action record (design §40).
type AuditEntry struct {
	Time     time.Time `json:"time"`
	User     string    `json:"user"`
	SourceIP string    `json:"source_ip,omitempty"`
	Action   string    `json:"action"`
	Object   string    `json:"object,omitempty"`
	Old      string    `json:"old,omitempty"`
	New      string    `json:"new,omitempty"`
	Result   string    `json:"result"`
}

// Event is a system event (design §29).
type Event struct {
	ID     uint64    `json:"id"`
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
}

// Store is a JSON-file-backed persistent store with in-memory indexes.
type Store struct {
	mu  sync.RWMutex
	dir string

	active  models.Config
	revs    []RevMeta // newest first
	revData map[int][]byte

	audit    []AuditEntry // newest first
	events   []Event      // newest first
	eventSeq uint64
	aliases  map[string]string
}

// Open loads or initializes a store rooted at dir (design §38).
func Open(dir string) (*Store, error) {
	for _, sub := range []string{dir, filepath.Join(dir, "backups")} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			return nil, err
		}
	}
	s := &Store{dir: dir, revData: map[int][]byte{}, aliases: map[string]string{}}
	if err := s.loadConfig(); err != nil {
		return nil, err
	}
	s.loadIndex()
	s.loadAudit()
	s.loadEvents()
	s.loadAliases()
	return s, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

func (s *Store) loadConfig() error {
	data, err := os.ReadFile(s.path("config.json"))
	if os.IsNotExist(err) {
		s.active = config.Default()
		s.revs = []RevMeta{{Rev: 1, Time: time.Now().UTC(), Author: "system", Message: "initial configuration"}}
		return s.writeActive()
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.active); err != nil {
		return fmt.Errorf("load config.json: %w", err)
	}
	return nil
}

func (s *Store) writeActive() error {
	return config.SaveFile(s.path("config.json"), s.active)
}

func (s *Store) loadIndex() {
	data, err := os.ReadFile(s.path("revisions.json"))
	if err != nil {
		// Seed history with the current (revision 1) config.
		if len(s.revs) == 1 && s.revs[0].Rev == 1 {
			s.revs[0].Time = time.Now().UTC()
			if err := s.appendRevision(1, s.revs[0].Author, s.revs[0].Message, s.active); err != nil {
				_ = err
			}
			// appendRevision prepended a fresh entry; drop the seed entry.
			s.revs = s.revs[:1]
			s.saveIndex()
		}
		return
	}
	if err := json.Unmarshal(data, &s.revs); err != nil {
		s.revs = nil
		return
	}
	for _, m := range s.revs {
		if b, err := os.ReadFile(s.revPath(m.Rev)); err == nil {
			s.revData[m.Rev] = b
		}
	}
}

func (s *Store) revPath(rev int) string {
	return filepath.Join(s.dir, "backups", fmt.Sprintf("rev-%06d.json", rev))
}

func (s *Store) saveIndex() {
	b, _ := json.MarshalIndent(s.revs, "", "  ")
	os.WriteFile(s.path("revisions.json"), b, 0o600)
}

func (s *Store) appendRevision(rev int, author, message string, c models.Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.revPath(rev), data, 0o600); err != nil {
		return err
	}
	s.revData[rev] = data
	meta := RevMeta{Rev: rev, Time: time.Now().UTC(), Author: author, Message: message}
	s.revs = append([]RevMeta{meta}, s.revs...)
	// retention
	for len(s.revs) > MaxRevisions {
		oldest := s.revs[len(s.revs)-1]
		s.revs = s.revs[:len(s.revs)-1]
		os.Remove(s.revPath(oldest.Rev))
		delete(s.revData, oldest.Rev)
	}
	return nil
}

// Current returns the active configuration and its metadata.
func (s *Store) Current() (models.Config, RevMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	meta := RevMeta{}
	if len(s.revs) > 0 {
		meta = s.revs[0]
	}
	return cloneConfig(s.active), meta, nil
}

func cloneConfig(c models.Config) models.Config {
	b, _ := json.Marshal(c)
	var out models.Config
	json.Unmarshal(b, &out)
	return out
}

// Revisions lists revision metadata, newest first.
func (s *Store) Revisions() []RevMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RevMeta, len(s.revs))
	copy(out, s.revs)
	return out
}

// Revision returns the stored configuration for a past revision.
func (s *Store) Revision(rev int) (models.Config, RevMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var meta RevMeta
	found := false
	for _, m := range s.revs {
		if m.Rev == rev {
			meta, found = m, true
		}
	}
	if !found {
		return models.Config{}, RevMeta{}, fmt.Errorf("unknown revision %d", rev)
	}
	data, ok := s.revData[rev]
	if !ok {
		return models.Config{}, RevMeta{}, fmt.Errorf("revision %d data missing", rev)
	}
	var c models.Config
	if err := json.Unmarshal(data, &c); err != nil {
		return models.Config{}, RevMeta{}, err
	}
	return c, meta, nil
}

// Save persists a new configuration revision. Identical configs are a no-op.
func (s *Store) Save(c models.Config, author, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sameConfig(s.active, c) {
		return nil
	}
	old, _ := json.Marshal(s.active)
	next := 1
	if len(s.revs) > 0 {
		next = s.revs[0].Rev + 1
	}
	if err := s.appendRevision(next, author, message, c); err != nil {
		return err
	}
	s.active = c
	if err := s.writeActive(); err != nil {
		return err
	}
	s.saveIndex()
	_ = old
	return nil
}

// Restore re-applies a past revision as a new revision.
func (s *Store) Restore(rev int, author string) error {
	c, meta, err := s.Revision(rev)
	if err != nil {
		return err
	}
	return s.Save(c, author, fmt.Sprintf("restored from revision %d (%s)", rev, meta.Message))
}

func sameConfig(a, b models.Config) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// --- audit ---

func (s *Store) loadAudit() {
	data, _ := os.ReadFile(s.path("audit.jsonl"))
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			s.audit = append([]AuditEntry{e}, s.audit...)
		}
	}
	if len(s.audit) > 2000 {
		s.audit = s.audit[:2000]
	}
}

// Audit appends a security-relevant audit record.
func (s *Store) Audit(e AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	s.audit = append([]AuditEntry{e}, s.audit...)
	if len(s.audit) > 2000 {
		s.audit = s.audit[:2000]
	}
	f, err := os.OpenFile(s.path("audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		b, _ := json.Marshal(e)
		f.Write(append(b, '\n'))
		f.Close()
	}
}

// AuditLog returns audit entries, newest first.
func (s *Store) AuditLog(limit int) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.audit) {
		limit = len(s.audit)
	}
	out := make([]AuditEntry, limit)
	copy(out, s.audit[:limit])
	return out
}

// --- events ---

func (s *Store) loadEvents() {
	data, _ := os.ReadFile(s.path("events.jsonl"))
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e Event
		if json.Unmarshal([]byte(line), &e) == nil {
			s.events = append([]Event{e}, s.events...)
			if e.ID > s.eventSeq {
				s.eventSeq = e.ID
			}
		}
	}
	if len(s.events) > EventRingSize {
		s.events = s.events[:EventRingSize]
	}
}

// Event records a system event.
func (s *Store) Event(e Event) Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventSeq++
	e.ID = s.eventSeq
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	s.events = append([]Event{e}, s.events...)
	if len(s.events) > EventRingSize {
		s.events = s.events[:EventRingSize]
	}
	f, err := os.OpenFile(s.path("events.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		b, _ := json.Marshal(e)
		f.Write(append(b, '\n'))
		f.Close()
	}
	return e
}

// Events returns events with ID > since (0 = all buffered), newest first.
func (s *Store) Events(since uint64) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Event
	for _, e := range s.events {
		if e.ID > since {
			out = append(out, e)
		}
	}
	return out
}

// --- device aliases ---

func (s *Store) loadAliases() {
	data, _ := os.ReadFile(s.path("devices.json"))
	json.Unmarshal(data, &s.aliases)
	if s.aliases == nil {
		s.aliases = map[string]string{}
	}
}

// DeviceAliases returns MAC→friendly-name mappings.
func (s *Store) DeviceAliases() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.aliases))
	for k, v := range s.aliases {
		out[k] = v
	}
	return out
}

// SetDeviceAlias sets or clears (empty name) a device alias.
func (s *Store) SetDeviceAlias(mac, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mac = strings.ToLower(mac)
	if name == "" {
		delete(s.aliases, mac)
	} else {
		s.aliases[mac] = name
	}
	b, _ := json.MarshalIndent(s.aliases, "", "  ")
	return os.WriteFile(s.path("devices.json"), b, 0o600)
}

// Close flushes nothing extra (writes are synchronous).
func (s *Store) Close() {}
