package store

import (
	"strconv"
	"testing"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesDefaultConfig(t *testing.T) {
	s := openStore(t)
	c, meta, err := s.Current()
	if err != nil {
		t.Fatal(err)
	}
	if c.Version == 0 || meta.Rev != 1 {
		t.Fatalf("unexpected first revision: %+v", meta)
	}
	if len(c.Networks) != 1 {
		t.Fatal("expected default config")
	}
}

func TestSaveCreatesRevisions(t *testing.T) {
	s := openStore(t)
	c, _, _ := s.Current()
	c.Networks[0].Name = "office"
	if err := s.Save(c, "admin", "rename lan"); err != nil {
		t.Fatal(err)
	}
	c2, meta, _ := s.Current()
	if c2.Networks[0].Name != "office" || meta.Rev != 2 {
		t.Fatalf("save failed: %+v", meta)
	}
	revs := s.Revisions()
	if len(revs) != 2 {
		t.Fatalf("expected 2 revisions, got %d", len(revs))
	}
	if revs[0].Rev != 2 {
		t.Fatal("newest first expected")
	}
	if revs[0].Author != "admin" || revs[0].Message != "rename lan" {
		t.Fatalf("meta not stored: %+v", revs[0])
	}
	if revs[0].Time.IsZero() {
		t.Fatal("time not stored")
	}
}

func TestSaveNoopOnIdenticalConfig(t *testing.T) {
	s := openStore(t)
	c, _, _ := s.Current()
	if err := s.Save(c, "admin", "noop"); err != nil {
		t.Fatal(err)
	}
	if revs := s.Revisions(); len(revs) != 1 {
		t.Fatalf("identical save should not create revision, got %d", len(revs))
	}
}

func TestRestoreRevision(t *testing.T) {
	s := openStore(t)
	c, _, _ := s.Current()
	c.Networks[0].Name = "changed"
	s.Save(c, "admin", "change")
	if err := s.Restore(1, "admin"); err != nil {
		t.Fatal(err)
	}
	cur, meta, _ := s.Current()
	if cur.Networks[0].Name != "lan" {
		t.Fatalf("restore failed: %+v", cur.Networks[0])
	}
	if meta.Rev != 3 {
		t.Fatalf("restore should append new revision, got %+v", meta)
	}
	if _, _, err := s.Revision(99); err == nil {
		t.Fatal("expected error for unknown revision")
	}
}

func TestRevisionContent(t *testing.T) {
	s := openStore(t)
	c, _, _ := s.Current()
	c.Networks[0].Name = "changed"
	s.Save(c, "admin", "change")
	old, meta, err := s.Revision(1)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Rev != 1 || old.Networks[0].Name != "lan" {
		t.Fatalf("bad revision content: %+v", meta)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := s.Current()
	c.System.Hostname = "gw01"
	s.Save(c, "admin", "hostname")
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	c2, meta, _ := s2.Current()
	if c2.System.Hostname != "gw01" || meta.Rev != 2 {
		t.Fatalf("persistence failed: %+v %+v", c2.System, meta)
	}
}

func TestAuditLog(t *testing.T) {
	s := openStore(t)
	s.Audit(AuditEntry{User: "admin", SourceIP: "127.0.0.1", Action: "create", Object: "firewall_rule r1", Result: "ok"})
	s.Audit(AuditEntry{User: "admin", Action: "login", Result: "fail"})
	entries := s.AuditLog(10)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries got %d", len(entries))
	}
	if entries[0].Action != "login" {
		t.Fatal("newest first expected")
	}
	if entries[0].Time.IsZero() {
		t.Fatal("audit time missing")
	}
}

func TestEvents(t *testing.T) {
	s := openStore(t)
	s.Event(Event{Kind: "wan.up", Detail: "eth0"})
	s.Event(Event{Kind: "lease.granted", Detail: "192.168.1.100"})
	evs := s.Events(0)
	if len(evs) != 2 || evs[0].Kind != "lease.granted" {
		t.Fatalf("bad events: %+v", evs)
	}
	if evs[0].ID != 2 {
		t.Fatalf("event ids should increase: %+v", evs[0])
	}
	// ring buffer bound
	for i := 0; i < EventRingSize+10; i++ {
		s.Event(Event{Kind: "flood"})
	}
	if got := len(s.Events(0)); got != EventRingSize {
		t.Fatalf("ring not bounded: %d", got)
	}
	// since filter: nothing newer than the newest event
	all := s.Events(0)
	if len(all) == 0 || all[0].ID != evs[0].ID+uint64(EventRingSize+10) {
		t.Fatalf("event sequencing broken: newest=%+v", all[0])
	}
	if got := s.Events(all[0].ID); len(got) != 0 {
		t.Fatalf("since filter broken: %d events newer than newest", len(got))
	}
}

func TestDeviceAliases(t *testing.T) {
	s := openStore(t)
	if err := s.SetDeviceAlias("aa:bb:cc:dd:ee:ff", "Living Room TV"); err != nil {
		t.Fatal(err)
	}
	m := s.DeviceAliases()
	if m["aa:bb:cc:dd:ee:ff"] != "Living Room TV" {
		t.Fatalf("alias not stored: %v", m)
	}
	if err := s.SetDeviceAlias("aa:bb:cc:dd:ee:ff", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.DeviceAliases()["aa:bb:cc:dd:ee:ff"]; ok {
		t.Fatal("empty alias should delete")
	}
}

func TestRevisionRetention(t *testing.T) {
	s := openStore(t)
	for i := 0; i < MaxRevisions+10; i++ {
		c, _, _ := s.Current()
		c.System.Hostname = fmtHost(i)
		s.Save(c, "admin", "churn")
	}
	if got := len(s.Revisions()); got > MaxRevisions {
		t.Fatalf("retention broken: %d", got)
	}
}

func fmtHost(i int) string { return "host" + strconv.Itoa(i) }
