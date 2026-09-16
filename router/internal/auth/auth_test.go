package auth

import (
	"testing"
	"time"
)

func openMgr(t *testing.T) *Manager {
	t.Helper()
	m, err := Open(t.TempDir() + "/auth.json")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if h == "correct horse battery staple" {
		t.Fatal("plaintext!")
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("verify failed")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("hashes must be salted")
	}
}

func TestDefaultAdminCreated(t *testing.T) {
	m := openMgr(t)
	pw, created, err := m.EnsureAdmin("")
	if err != nil {
		t.Fatal(err)
	}
	if !created || pw == "" {
		t.Fatal("expected generated admin password")
	}
	u, ok := m.User("admin")
	if !ok || u.Role != RoleAdmin {
		t.Fatal("admin user missing")
	}
	if !VerifyPassword(pw, u.PassHash) {
		t.Fatal("generated password mismatch")
	}
	// explicit password
	m2 := openMgr(t)
	pw2, created2, _ := m2.EnsureAdmin("hunter2")
	if !created2 || pw2 != "hunter2" {
		t.Fatal("expected provided password to be set on fresh store")
	}
}

func TestSetPassword(t *testing.T) {
	m := openMgr(t)
	m.EnsureAdmin("old-pass")
	if err := m.SetPassword("admin", "new-pass"); err != nil {
		t.Fatal(err)
	}
	u, _ := m.User("admin")
	if !VerifyPassword("new-pass", u.PassHash) {
		t.Fatal("password not updated")
	}
	if err := m.SetPassword("ghost", "x"); err == nil {
		t.Fatal("unknown user error expected")
	}
}

func TestSessions(t *testing.T) {
	m := openMgr(t)
	m.EnsureAdmin("pw")
	sess, err := m.Login("admin", "pw", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Token == "" || sess.Expires.Before(time.Now()) {
		t.Fatalf("bad session: %+v", sess)
	}
	s, ok := m.Check(sess.Token)
	if !ok || s.User != "admin" || s.Role != RoleAdmin || s.SourceIP != "10.0.0.5" {
		t.Fatalf("session check failed: %+v", s)
	}
	if _, ok := m.Check("bogus"); ok {
		t.Fatal("bogus token accepted")
	}
	m.Logout(sess.Token)
	if _, ok := m.Check(sess.Token); ok {
		t.Fatal("token usable after logout")
	}
	if _, err := m.Login("admin", "bad", ""); err == nil {
		t.Fatal("bad password accepted")
	}
}

func TestSessionExpiry(t *testing.T) {
	m := openMgr(t)
	m.EnsureAdmin("pw")
	sess, _ := m.Login("admin", "pw", "")
	m.mu.Lock()
	sess.Expires = time.Now().Add(-time.Minute)
	m.mu.Unlock()
	if _, ok := m.Check(sess.Token); ok {
		t.Fatal("expired session accepted")
	}
}

func TestAPITokens(t *testing.T) {
	m := openMgr(t)
	tok, err := m.CreateToken("backup-agent", RoleReadonly)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token == "" || tok.Role != RoleReadonly {
		t.Fatalf("bad token: %+v", tok)
	}
	s, ok := m.Check(tok.Token)
	if !ok || s.Role != RoleReadonly || !s.API {
		t.Fatalf("token check: %+v %v", s, ok)
	}
	toks := m.Tokens()
	if len(toks) != 1 || toks[0].Name != "backup-agent" {
		t.Fatalf("token list: %+v", toks)
	}
	if err := m.RevokeToken(toks[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Check(tok.Token); ok {
		t.Fatal("revoked token accepted")
	}
}

func TestTokenPersistence(t *testing.T) {
	dir := t.TempDir()
	m, _ := Open(dir + "/auth.json")
	tok, _ := m.CreateToken("ci", RoleAdmin)
	m2, err := Open(dir + "/auth.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.Check(tok.Token); !ok {
		t.Fatal("token not persisted")
	}
}

func TestRoles(t *testing.T) {
	if !AtLeast(RoleAdmin, RoleReadonly) {
		t.Fatal("admin >= readonly")
	}
	if AtLeast(RoleReadonly, RoleAdmin) {
		t.Fatal("readonly !>= admin")
	}
	if !AtLeast(RoleAdmin, RoleAdmin) {
		t.Fatal("admin >= admin")
	}
}
