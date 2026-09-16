// Package auth provides local administrator accounts, hashed passwords,
// sessions and API tokens (design §34/§35).
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Roles (design §35).
const (
	RoleAdmin    = "admin"
	RoleReadonly = "readonly"
)

// Session is an authenticated identity behind a bearer token.
type Session struct {
	Token    string    `json:"-"`
	User     string    `json:"user"`
	Role     string    `json:"role"`
	SourceIP string    `json:"source_ip,omitempty"`
	Expires  time.Time `json:"expires"`
	API      bool      `json:"api"`
}

// APIToken is a long-lived programmable credential.
type APIToken struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Role     string    `json:"role"`
	Hash     string    `json:"hash"`
	Token    string    `json:"token,omitempty"` // present once at creation
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitempty"`
}

// User is a local administrator account.
type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	PassHash string `json:"pass_hash"`
}

// Manager persists users/tokens and tracks sessions.
type Manager struct {
	mu     sync.Mutex
	path   string
	users  map[string]*User
	tokens []*APIToken
	sess   map[string]*Session
}

// Open loads (or initializes) the auth database.
func Open(path string) (*Manager, error) {
	m := &Manager{path: path, users: map[string]*User{}, sess: map[string]*Session{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return m, nil
	}
	var persist struct {
		Users  []*User     `json:"users"`
		Tokens []*APIToken `json:"tokens"`
	}
	if err := json.Unmarshal(data, &persist); err != nil {
		return nil, fmt.Errorf("auth db: %w", err)
	}
	for _, u := range persist.Users {
		m.users[u.Username] = u
	}
	m.tokens = persist.Tokens
	return m, nil
}

func (m *Manager) save() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	persist := struct {
		Users  []*User     `json:"users"`
		Tokens []*APIToken `json:"tokens"`
	}{Tokens: m.tokens}
	for _, u := range m.users {
		persist.Users = append(persist.Users, u)
	}
	b, _ := json.MarshalIndent(persist, "", "  ")
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// HashPassword derives a PBKDF2-HMAC-SHA256 hash (150k iterations).
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, 150_000, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$150000$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword checks a password against a stored hash.
func VerifyPassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	var iter int
	fmt.Sscanf(parts[1], "%d", &iter)
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || iter <= 0 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// EnsureAdmin guarantees an admin account exists. If one exists already,
// it returns ("", false, nil). Otherwise it creates it using the given
// password (randomly generated when empty) and returns the password used.
func (m *Manager) EnsureAdmin(password string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users["admin"]; ok && u.Role == RoleAdmin {
		return "", false, nil
	}
	if password == "" {
		b := make([]byte, 12)
		rand.Read(b)
		password = hex.EncodeToString(b)
	}
	h, err := HashPassword(password)
	if err != nil {
		return "", false, err
	}
	m.users["admin"] = &User{Username: "admin", Role: RoleAdmin, PassHash: h}
	if err := m.save(); err != nil {
		return "", false, err
	}
	return password, true, nil
}

// User returns a user record.
func (m *Manager) User(name string) (User, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[name]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// Users lists accounts without hashes.
func (m *Manager) Users() []User {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []User
	for _, u := range m.users {
		c := *u
		c.PassHash = ""
		out = append(out, c)
	}
	return out
}

// SetPassword changes an account password.
func (m *Manager) SetPassword(username, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok {
		return errors.New("unknown user")
	}
	h, err := HashPassword(password)
	if err != nil {
		return err
	}
	u.PassHash = h
	return m.save()
}

// Login validates credentials and creates a session.
func (m *Manager) Login(username, password, ip string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok || !VerifyPassword(password, u.PassHash) {
		// constant-ish time on unknown user
		VerifyPassword(password, "pbkdf2-sha256$1$AA$AA")
		return nil, errors.New("invalid credentials")
	}
	tok := randomToken("sess_")
	s := &Session{Token: tok, User: username, Role: u.Role, SourceIP: ip,
		Expires: time.Now().Add(8 * time.Hour)}
	m.sess[tok] = s
	return s, nil
}

// Logout destroys a session.
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sess, token)
}

// Check resolves a bearer token to an identity (session or API token).
func (m *Manager) Check(token string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sess[token]; ok {
		if time.Now().After(s.Expires) {
			delete(m.sess, token)
			return nil, false
		}
		c := *s
		return &c, true
	}
	for _, t := range m.tokens {
		if hmac.Equal([]byte(HashToken(token)), []byte(t.Hash)) {
			t.LastUsed = time.Now().UTC()
			m.save()
			return &Session{User: "token:" + t.Name, Role: t.Role,
				Expires: time.Now().Add(24 * time.Hour), API: true}, true
		}
	}
	return nil, false
}

// HashToken hashes API tokens at rest (SHA-256).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateToken issues a persistent API token.
func (m *Manager) CreateToken(name, role string) (*APIToken, error) {
	if role != RoleAdmin && role != RoleReadonly {
		return nil, errors.New("invalid role")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	raw := randomToken("rtk_")
	t := &APIToken{ID: randomToken(""), Name: name, Role: role,
		Hash: HashToken(raw), Created: time.Now().UTC(), Token: raw}
	m.tokens = append(m.tokens, t)
	if err := m.save(); err != nil {
		return nil, err
	}
	out := *t
	t.Token = "" // never persist the raw token again
	m.save()
	return &out, nil
}

// Tokens lists API tokens (without secrets).
func (m *Manager) Tokens() []APIToken {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []APIToken{}
	for _, t := range m.tokens {
		c := *t
		c.Hash = ""
		c.Token = ""
		out = append(out, c)
	}
	return out
}

// RevokeToken removes an API token.
func (m *Manager) RevokeToken(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tokens {
		if t.ID == id {
			m.tokens = append(m.tokens[:i], m.tokens[i+1:]...)
			return m.save()
		}
	}
	return errors.New("unknown token")
}

// AtLeast reports whether have meets the required role level.
func AtLeast(have, want string) bool {
	rank := map[string]int{RoleReadonly: 1, RoleAdmin: 2}
	return rank[have] >= rank[want] && rank[have] > 0
}

func randomToken(prefix string) string {
	b := make([]byte, 24)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
