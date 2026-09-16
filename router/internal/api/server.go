// Package api implements the versioned REST management API (design §31).
// Both the CLI and the web UI speak this API; nothing else may change
// router state.
package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"router/internal/auth"
	"router/internal/config"
	"router/internal/dhcp"
	"router/internal/monitor"
	"router/internal/platform"
	"router/internal/reconcile"
	"router/internal/state"
	"router/internal/store"
	"router/internal/wireguard"
	"router/pkg/models"
	"router/web"
)

// Version is the routerd version string.
var Version = "0.1.0-dev"

// Options configures the management server.
type Options struct {
	DataDir       string
	Exec          platform.Executor
	Src           any // optional LeaseSource/WANStatusProvider
	AdminPassword string
	Version       string
}

// Server is the routerd management API server.
type Server struct {
	opt     Options
	st      *store.Store
	auth    *auth.Manager
	engine  *reconcile.Engine
	monitor *monitor.Monitor

	mu     sync.Mutex
	pend   *pendingCommit
	txns   map[string]*transaction
	auditQ chan store.AuditEntry
	start  time.Time
}

type pendingCommit struct {
	cfg    models.Config
	token  string
	txnID  string
	timer  *time.Timer
	expiry time.Time
}

type transaction struct {
	id    string
	draft models.Config
	base  models.Config // effective config at apply time (for rollback)
}

// New initializes a management server (stores, auth, engine).
func New(o Options) (*Server, error) {
	if o.Version == "" {
		o.Version = Version
	}
	st, err := store.Open(o.DataDir)
	if err != nil {
		return nil, err
	}
	am, err := auth.Open(filepath.Join(o.DataDir, "auth.json"))
	if err != nil {
		return nil, err
	}
	pw, created, err := am.EnsureAdmin(o.AdminPassword)
	if err != nil {
		return nil, err
	}
	if created && o.AdminPassword == "" {
		p := filepath.Join(o.DataDir, "initial-admin-password")
		os.WriteFile(p, []byte(pw+"\n"), 0o600)
	}
	s := &Server{
		opt: o, st: st, auth: am,
		engine: reconcile.NewEngine(o.Exec, reconcile.NewFileProvenance(o.Exec,
			filepath.Join(o.DataDir, "routes.mgmt.json"))),
		monitor: monitor.New(o.Exec, o.Src),
		txns:    map[string]*transaction{},
		start:   time.Now(),
	}
	s.syncAliases()
	return s, nil
}

// NewTestEnv builds a server over a simulated platform for tests.
func NewTestEnv(dir string, f *platform.Fake, adminPw string) (*Server, error) {
	return New(Options{DataDir: dir, Exec: f, Src: f, AdminPassword: adminPw, Version: "test"})
}

// Handler returns the fully routed HTTP handler.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /api/v1/auth/login", s.hLogin)
	m.HandleFunc("POST /api/v1/auth/logout", s.authOnly(RoleAdminAll, s.hLogout))
	m.HandleFunc("GET /api/v1/auth/whoami", s.authOnly(RoleAdminAll, s.hWhoami))
	m.HandleFunc("POST /api/v1/auth/password", s.authOnly(RoleAdminAll, s.hPassword))
	m.HandleFunc("GET /api/v1/auth/tokens", s.authOnly(auth.RoleAdmin, s.hTokensList))
	m.HandleFunc("POST /api/v1/auth/tokens", s.authOnly(auth.RoleAdmin, s.hTokensCreate))
	m.HandleFunc("DELETE /api/v1/auth/tokens/{id}", s.authOnly(auth.RoleAdmin, s.hTokensDelete))

	m.HandleFunc("GET /api/v1/system", s.authOnly(auth.RoleReadonly, s.hSystem))
	m.HandleFunc("GET /api/v1/health", s.authOnly(auth.RoleReadonly, s.hHealth))
	m.HandleFunc("GET /api/v1/interfaces", s.authOnly(auth.RoleReadonly, s.hInterfaces))
	m.HandleFunc("GET /api/v1/interfaces/{name}", s.authOnly(auth.RoleReadonly, s.hInterface))

	m.HandleFunc("GET /api/v1/networks", s.authOnly(auth.RoleReadonly, s.hNetworksList))
	m.HandleFunc("POST /api/v1/networks", s.authOnly(auth.RoleAdmin, s.hNetworkAdd))
	m.HandleFunc("GET /api/v1/networks/{id}", s.authOnly(auth.RoleReadonly, s.hNetworkGet))
	m.HandleFunc("PATCH /api/v1/networks/{id}", s.authOnly(auth.RoleAdmin, s.hNetworkPatch))
	m.HandleFunc("PUT /api/v1/networks/{id}", s.authOnly(auth.RoleAdmin, s.hNetworkPatch))
	m.HandleFunc("DELETE /api/v1/networks/{id}", s.authOnly(auth.RoleAdmin, s.hNetworkDelete))

	m.HandleFunc("GET /api/v1/routes", s.authOnly(auth.RoleReadonly, s.hRoutes))
	m.HandleFunc("POST /api/v1/routes", s.authOnly(auth.RoleAdmin, s.hRouteAdd))
	m.HandleFunc("DELETE /api/v1/routes/{id}", s.authOnly(auth.RoleAdmin, s.hRouteDelete))

	m.HandleFunc("GET /api/v1/firewall/rules", s.authOnly(auth.RoleReadonly, s.hRulesList))
	m.HandleFunc("POST /api/v1/firewall/rules", s.authOnly(auth.RoleAdmin, s.hRuleAdd))
	m.HandleFunc("PATCH /api/v1/firewall/rules/{id}", s.authOnly(auth.RoleAdmin, s.hRulePatch))
	m.HandleFunc("PUT /api/v1/firewall/rules/{id}", s.authOnly(auth.RoleAdmin, s.hRulePatch))
	m.HandleFunc("DELETE /api/v1/firewall/rules/{id}", s.authOnly(auth.RoleAdmin, s.hRuleDelete))

	m.HandleFunc("GET /api/v1/portforwards", s.authOnly(auth.RoleReadonly, s.hPFList))
	m.HandleFunc("POST /api/v1/portforwards", s.authOnly(auth.RoleAdmin, s.hPFAdd))
	m.HandleFunc("PATCH /api/v1/portforwards/{id}", s.authOnly(auth.RoleAdmin, s.hPFPatch))
	m.HandleFunc("PUT /api/v1/portforwards/{id}", s.authOnly(auth.RoleAdmin, s.hPFPatch))
	m.HandleFunc("DELETE /api/v1/portforwards/{id}", s.authOnly(auth.RoleAdmin, s.hPFDelete))

	m.HandleFunc("GET /api/v1/wireguard/tunnels", s.authOnly(auth.RoleReadonly, s.hWGTunnels))
	m.HandleFunc("POST /api/v1/wireguard/tunnels", s.authOnly(auth.RoleAdmin, s.hWGAdd))
	m.HandleFunc("DELETE /api/v1/wireguard/tunnels/{name}", s.authOnly(auth.RoleAdmin, s.hWGDelete))

	m.HandleFunc("GET /api/v1/devices", s.authOnly(auth.RoleReadonly, s.hDevices))
	m.HandleFunc("PUT /api/v1/devices/{mac}", s.authOnly(auth.RoleAdmin, s.hDeviceName))
	m.HandleFunc("GET /api/v1/wan/status", s.authOnly(auth.RoleReadonly, s.hWANStatus))
	m.HandleFunc("GET /api/v1/services", s.authOnly(auth.RoleReadonly, s.hServices))
	m.HandleFunc("GET /api/v1/config/dhcp", s.authOnly(auth.RoleReadonly, s.hDHCPStatus))
	m.HandleFunc("GET /api/v1/leases", s.authOnly(auth.RoleReadonly, s.hLeases))
	m.HandleFunc("GET /api/v1/events", s.authOnly(auth.RoleReadonly, s.hEvents))
	m.HandleFunc("GET /api/v1/audit", s.authOnly(auth.RoleAdmin, s.hAudit))

	m.HandleFunc("GET /api/v1/config", s.authOnly(auth.RoleReadonly, s.hConfigGet))
	m.HandleFunc("PUT /api/v1/config", s.authOnly(auth.RoleAdmin, s.hConfigPut))
	m.HandleFunc("POST /api/v1/config/validate", s.authOnly(auth.RoleAdmin, s.hConfigValidate))
	m.HandleFunc("GET /api/v1/config/revisions", s.authOnly(auth.RoleReadonly, s.hRevisions))
	m.HandleFunc("GET /api/v1/config/revisions/{rev}", s.authOnly(auth.RoleReadonly, s.hRevisionGet))
	m.HandleFunc("POST /api/v1/config/revisions/{rev}/restore", s.authOnly(auth.RoleAdmin, s.hRevisionRestore))
	m.HandleFunc("GET /api/v1/config/pending", s.authOnly(auth.RoleReadonly, s.hPending))
	m.HandleFunc("POST /api/v1/config/commit", s.authOnly(auth.RoleAdmin, s.hCommit))
	m.HandleFunc("POST /api/v1/config/rollback", s.authOnly(auth.RoleAdmin, s.hRollback))

	m.HandleFunc("POST /api/v1/transactions", s.authOnly(auth.RoleAdmin, s.hTxnBegin))
	m.HandleFunc("GET /api/v1/transactions/{id}", s.authOnly(auth.RoleAdmin, s.hTxnGet))
	m.HandleFunc("PUT /api/v1/transactions/{id}/config", s.authOnly(auth.RoleAdmin, s.hTxnConfig))
	m.HandleFunc("POST /api/v1/transactions/{id}/validate", s.authOnly(auth.RoleAdmin, s.hTxnValidate))
	m.HandleFunc("POST /api/v1/transactions/{id}/apply", s.authOnly(auth.RoleAdmin, s.hTxnApply))
	m.HandleFunc("POST /api/v1/transactions/{id}/commit", s.authOnly(auth.RoleAdmin, s.hTxnCommit))
	m.HandleFunc("POST /api/v1/transactions/{id}/rollback", s.authOnly(auth.RoleAdmin, s.hTxnRollback))
	m.HandleFunc("DELETE /api/v1/transactions/{id}", s.authOnly(auth.RoleAdmin, s.hTxnRollback))

	m.HandleFunc("GET /metrics", s.authOnly(auth.RoleReadonly, s.hMetrics))

	// management UI (embedded SPA); the /api/... patterns above are more
	// specific and always win over this catch-all
	m.Handle("GET /", web.Handler())
	return s.recoverWare(m)
}

// ListenAndServe starts the server (HTTPS when a cert is configured or
// generated).
func (s *Server) ListenAndServe(addr string, certPath, keyPath string) error {
	cert, key, err := s.resolveCerts(certPath, keyPath)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second}
	if cert != "" {
		return srv.ListenAndServeTLS(cert, key)
	}
	return srv.ListenAndServe()
}

func (s *Server) resolveCerts(certPath, keyPath string) (string, string, error) {
	if certPath != "" && keyPath != "" {
		return certPath, keyPath, nil
	}
	certPath = filepath.Join(s.opt.DataDir, "tls.crt")
	keyPath = filepath.Join(s.opt.DataDir, "tls.key")
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, nil
	}
	if err := generateSelfSigned(certPath, keyPath); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func generateSelfSigned(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "routerd"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"routerd", "localhost"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	kf.Close()
	return nil
}

// --- middleware / helpers ---

// RoleAdminAll is a sentinel meaning "any authenticated role".
const RoleAdminAll = ""

type ctxKey int

type identity struct {
	sess *auth.Session
	ip   string
}

func (s *Server) recoverWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeErr(w, 500, fmt.Sprintf("internal error: %v", rec))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authOnly(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sess, ok := s.auth.Check(tok)
		if !ok {
			writeErr(w, 401, "unauthorized")
			return
		}
		if role != RoleAdminAll && !auth.AtLeast(sess.Role, role) {
			writeErr(w, 403, "insufficient role")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey(0),
			identity{sess: sess, ip: clientIP(r)}))
		h(w, r)
	}
}

func who(r *http.Request) identity {
	v, _ := r.Context().Value(ctxKey(0)).(identity)
	return v
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	return dec.Decode(v)
}

func (s *Server) audit(r *http.Request, action, object, result string) {
	id := who(r)
	user, ip := "anonymous", clientIP(r)
	if id.sess != nil {
		user = id.sess.User
	}
	s.st.Audit(store.AuditEntry{User: user, SourceIP: ip, Action: action,
		Object: object, Result: result})
}

func (s *Server) event(kind, detail string) {
	s.st.Event(store.Event{Kind: kind, Detail: detail})
}

// --- auth handlers ---

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &b); err != nil {
		writeErr(w, 400, "bad request")
		return
	}
	sess, err := s.auth.Login(b.Username, b.Password, clientIP(r))
	if err != nil {
		s.audit(r, "login", b.Username, "fail")
		writeErr(w, 401, "invalid credentials")
		return
	}
	s.audit(r, "login", b.Username, "ok")
	s.event("auth.login", b.Username)
	writeJSON(w, 200, map[string]any{"token": sess.Token, "user": sess.User,
		"role": sess.Role, "expires": sess.Expires})
}

func (s *Server) hLogout(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.auth.Logout(tok)
	s.audit(r, "logout", who(r).sess.User, "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hWhoami(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	writeJSON(w, 200, map[string]any{"user": id.sess.User, "role": id.sess.Role, "api": id.sess.API})
}

func (s *Server) hPassword(w http.ResponseWriter, r *http.Request) {
	var b struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeBody(r, &b); err != nil || b.NewPassword == "" {
		writeErr(w, 400, "new_password required")
		return
	}
	id := who(r)
	uname := id.sess.User
	if strings.HasPrefix(uname, "token:") {
		writeErr(w, 400, "cannot change password for API tokens")
		return
	}
	u, _ := s.auth.User(uname)
	_ = u
	if _, err := s.auth.Login(uname, b.OldPassword, ""); err != nil {
		writeErr(w, 401, "old password incorrect")
		return
	}
	if err := s.auth.SetPassword(uname, b.NewPassword); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "password.change", uname, "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hTokensList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.auth.Tokens())
}

func (s *Server) hTokensCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := decodeBody(r, &b); err != nil || b.Name == "" {
		writeErr(w, 400, "name required")
		return
	}
	if b.Role == "" {
		b.Role = auth.RoleReadonly
	}
	t, err := s.auth.CreateToken(b.Name, b.Role)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "token.create", b.Name, "ok")
	writeJSON(w, 201, t)
}

func (s *Server) hTokensDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.auth.RevokeToken(id); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	s.audit(r, "token.revoke", id, "ok")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// --- system / state ---

func (s *Server) effectiveConfig() models.Config {
	s.mu.Lock()
	p := s.pend
	s.mu.Unlock()
	if p != nil {
		return p.cfg
	}
	c, _, _ := s.st.Current()
	return c
}

func (s *Server) committedConfig() models.Config {
	c, _, _ := s.st.Current()
	return c
}

func (s *Server) hSystem(w http.ResponseWriter, r *http.Request) {
	committed, meta, _ := s.st.Current()
	eff := s.effectiveConfig() // live state includes pending unconfirmed changes
	_ = committed
	h := s.monitor.Health(eff)
	writeJSON(w, 200, map[string]any{
		"hostname": eff.System.Hostname, "version": s.opt.Version,
		"revision": meta.Rev, "time": time.Now().UTC(),
		"uptime_seconds": int64(time.Since(s.start).Seconds()),
		"health":         h.Status,
		"go":             runtime.Version(),
	})
}

func (s *Server) hHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.monitor.Health(s.effectiveConfig()))
}

func (s *Server) observe(r *http.Request) (*reconcile.Actual, error) {
	return reconcile.Observe(r.Context(), s.opt.Exec)
}

func (s *Server) hInterfaces(w http.ResponseWriter, r *http.Request) {
	a, err := s.observe(r)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cfg := s.effectiveConfig()
	out := []map[string]any{}
	nets := map[string]string{}
	for _, n := range cfg.Networks {
		nets[n.Interface] = n.Name
	}
	for _, l := range a.Links {
		out = append(out, map[string]any{
			"name": l.Name, "type": l.Type, "up": l.Up, "mtu": l.MTU,
			"master": l.Master, "addrs": a.Addrs.By(l.Name).Addrs,
			"network": nets[l.Name], "stats": l.Stats,
		})
	}
	writeJSON(w, 200, out)
}

func (s *Server) hInterface(w http.ResponseWriter, r *http.Request) {
	a, err := s.observe(r)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	name := r.PathValue("name")
	l := a.Links.By(name)
	if l == nil {
		writeErr(w, 404, "interface not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"name": l.Name, "type": l.Type, "up": l.Up, "mtu": l.MTU,
		"master": l.Master, "addrs": a.Addrs.By(name).Addrs, "stats": l.Stats,
	})
}

// --- mutation pipeline (transactions + confirmed commits, §25-§27) ---

type applyOpts struct {
	message string
	confirm time.Duration
	object  string // audit object description
	created bool   // respond 201 instead of 200 on success
}

func confirmFrom(r *http.Request) time.Duration {
	if v := r.URL.Query().Get("confirm_seconds"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

// applyNewConfig validates and applies a new configuration; on success it
// either commits immediately or opens a confirmation window.
func (s *Server) applyNewConfig(w http.ResponseWriter, r *http.Request, next models.Config, o applyOpts, txnID string) {
	config.ApplyDefaults(&next)
	errs := models.Validate(next)
	if len(errs) > 0 {
		s.audit(r, "config.apply", o.object, "invalid")
		writeJSON(w, 400, map[string]any{"error": "invalid configuration",
			"fields": errs})
		return
	}
	base := s.effectiveConfig()
	s.mu.Lock()
	if s.pend != nil && s.pend.txnID != txnID {
		s.mu.Unlock()
		writeErr(w, 409, "a pending commit is already in progress")
		return
	}
	s.mu.Unlock()

	desired, err := reconcile.Build(next)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	ctx := r.Context()
	if _, err := s.engine.Apply(ctx, desired); err != nil {
		// roll the live system back to the previously effective state
		if bd, berr := reconcile.Build(base); berr == nil {
			s.engine.Apply(context.Background(), bd) //nolint:errcheck // best-effort recovery
		}
		s.audit(r, "config.apply", o.object, "error")
		s.event("config.apply_failed", err.Error())
		writeErr(w, 500, "apply failed: "+err.Error())
		return
	}
	if o.confirm > 0 {
		token := fmt.Sprintf("ct_%d", time.Now().UnixNano())
		s.mu.Lock()
		if s.pend != nil && s.pend.timer != nil {
			s.pend.timer.Stop()
		}
		s.pend = &pendingCommit{cfg: next, token: token, txnID: txnID,
			expiry: time.Now().Add(o.confirm)}
		s.pend.timer = time.AfterFunc(o.confirm, s.autoRollback)
		s.mu.Unlock()
		s.audit(r, "config.apply_pending", o.object, "ok")
		s.event("config.pending", o.message)
		writeJSON(w, 202, map[string]any{"status": "pending",
			"pending": map[string]any{"commit_token": token,
				"expires": time.Now().Add(o.confirm)},
			"operations": len(desired.Links)})
		return
	}
	if err := s.st.Save(next, actor(r), o.message); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// an immediate commit supersedes any pending window: disarm it so a
	// stale timer cannot auto-rollback the new committed state
	s.mu.Lock()
	if s.pend != nil && s.pend.timer != nil {
		s.pend.timer.Stop()
	}
	s.pend = nil
	s.mu.Unlock()
	s.audit(r, "config.apply", o.object, "ok")
	s.event("config.applied", o.message)
	code := 200
	if o.created {
		code = 201
	}
	writeJSON(w, code, map[string]any{"status": "committed"})
}

func actor(r *http.Request) string {
	if id := who(r); id.sess != nil {
		return id.sess.User
	}
	return "system"
}

func (s *Server) autoRollback() {
	s.mu.Lock()
	p := s.pend
	s.pend = nil
	s.mu.Unlock()
	if p == nil {
		return
	}
	if d, err := reconcile.Build(s.committedConfig()); err == nil {
		s.engine.Apply(context.Background(), d) //nolint:errcheck
	}
	s.st.Audit(store.AuditEntry{User: "system", Action: "config.auto_rollback",
		Object: p.txnID, Result: "ok"})
	s.st.Event(store.Event{Kind: "config.auto_rollback", Detail: "commit window expired"})
}

func (s *Server) commitPending(w http.ResponseWriter, r *http.Request, token string) {
	s.mu.Lock()
	p := s.pend
	if p == nil {
		s.mu.Unlock()
		writeErr(w, 409, "no pending change")
		return
	}
	if token != "" && p.token != token {
		s.mu.Unlock()
		writeErr(w, 403, "commit token mismatch")
		return
	}
	s.pend = nil
	if p.timer != nil {
		p.timer.Stop()
	}
	s.mu.Unlock()
	if err := s.st.Save(p.cfg, actor(r), "confirmed commit"); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, "config.commit", p.txnID, "ok")
	s.event("config.committed", "")
	writeJSON(w, 200, map[string]any{"status": "committed"})
}

func (s *Server) rollbackPending(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	p := s.pend
	s.pend = nil
	s.mu.Unlock()
	if p != nil && p.timer != nil {
		p.timer.Stop()
	}
	d, err := reconcile.Build(s.committedConfig())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if _, err := s.engine.Apply(context.Background(), d); err != nil {
		writeErr(w, 500, "rollback failed: "+err.Error())
		return
	}
	s.audit(r, "config.rollback", p.txnID, "ok")
	s.event("config.rolled_back", "")
	writeJSON(w, 200, map[string]any{"status": "rolled_back"})
}

func (s *Server) hCommit(w http.ResponseWriter, r *http.Request) {
	var b struct {
		CommitToken string `json:"commit_token"`
	}
	decodeBody(r, &b) //nolint:errcheck
	s.commitPending(w, r, b.CommitToken)
}

func (s *Server) hRollback(w http.ResponseWriter, r *http.Request) {
	s.rollbackPending(w, r)
}

func (s *Server) hPending(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	p := s.pend
	s.mu.Unlock()
	if p == nil {
		writeJSON(w, 200, map[string]any{"pending": nil})
		return
	}
	writeJSON(w, 200, map[string]any{"pending": map[string]any{
		"commit_token": p.token, "expires": p.expiry, "txn": p.txnID}})
}

// --- networks ---

func (s *Server) hNetworksList(w http.ResponseWriter, r *http.Request) {
	c := s.effectiveConfig()
	if c.Networks == nil {
		c.Networks = []models.Network{}
	}
	writeJSON(w, 200, c.Networks)
}

func (s *Server) hNetworkGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, n := range s.effectiveConfig().Networks {
		if n.ID == id || n.Name == id {
			writeJSON(w, 200, n)
			return
		}
	}
	writeErr(w, 404, "network not found")
}

func (s *Server) hNetworkAdd(w http.ResponseWriter, r *http.Request) {
	var n models.Network
	if err := decodeBody(r, &n); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if n.Name == "" {
		writeErr(w, 400, "name required")
		return
	}
	if n.ID == "" {
		n.ID = n.Name
	}
	c := s.effectiveConfig()
	for _, x := range c.Networks {
		if x.ID == n.ID || x.Name == n.Name {
			writeErr(w, 409, "network exists")
			return
		}
	}
	c.Networks = append(c.Networks, n)
	s.applyNewConfig(w, r, c, applyOpts{message: "network " + n.Name + " created", created: true,
		confirm: confirmFrom(r), object: "network " + n.Name}, "")
}

func (s *Server) hNetworkPatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var n models.Network
	if err := decodeBody(r, &n); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	c := s.effectiveConfig()
	for i := range c.Networks {
		if c.Networks[i].ID == id || c.Networks[i].Name == id {
			n.ID = c.Networks[i].ID
			c.Networks[i] = n
			s.applyNewConfig(w, r, c, applyOpts{message: "network " + id + " updated",
				confirm: confirmFrom(r), object: "network " + id}, "")
			return
		}
	}
	writeErr(w, 404, "network not found")
}

func (s *Server) hNetworkDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := s.effectiveConfig()
	for i := range c.Networks {
		if c.Networks[i].ID == id || c.Networks[i].Name == id {
			c.Networks = append(c.Networks[:i], c.Networks[i+1:]...)
			s.applyNewConfig(w, r, c, applyOpts{message: "network " + id + " deleted",
				confirm: confirmFrom(r), object: "network " + id}, "")
			return
		}
	}
	writeErr(w, 404, "network not found")
}

// --- routes ---

func (s *Server) hRoutes(w http.ResponseWriter, r *http.Request) {
	c := s.effectiveConfig()
	out := []map[string]any{}
	for _, r := range c.StaticRoutes {
		out = append(out, map[string]any{"id": r.ID, "dst": r.Destination,
			"via": r.Via, "dev": r.Device, "metric": r.Metric, "table": r.Table,
			"source": "config"})
	}
	if a, err := s.observe(r); err == nil {
		for _, r := range a.Routes {
			out = append(out, map[string]any{"dst": r.Dst, "via": r.Via,
				"dev": r.Dev, "metric": r.Metric, "table": r.Table,
				"protocol": r.Protocol, "source": "kernel"})
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) hRouteAdd(w http.ResponseWriter, r *http.Request) {
	var rt models.StaticRoute
	if err := decodeBody(r, &rt); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if rt.ID == "" {
		rt.ID = fmt.Sprintf("r%d", time.Now().UnixNano()%100000)
	}
	c := s.effectiveConfig()
	for _, x := range c.StaticRoutes {
		if x.ID == rt.ID {
			writeErr(w, 409, "route exists")
			return
		}
	}
	c.StaticRoutes = append(c.StaticRoutes, rt)
	s.applyNewConfig(w, r, c, applyOpts{message: "static route " + rt.ID, created: true,
		confirm: confirmFrom(r), object: "route " + rt.ID}, "")
}

func (s *Server) hRouteDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := s.effectiveConfig()
	for i := range c.StaticRoutes {
		if c.StaticRoutes[i].ID == id {
			c.StaticRoutes = append(c.StaticRoutes[:i], c.StaticRoutes[i+1:]...)
			s.applyNewConfig(w, r, c, applyOpts{message: "static route deleted " + id,
				confirm: confirmFrom(r), object: "route " + id}, "")
			return
		}
	}
	writeErr(w, 404, "route not found")
}

// --- firewall rules ---

func (s *Server) hRulesList(w http.ResponseWriter, r *http.Request) {
	c := s.effectiveConfig()
	if c.FirewallRules == nil {
		c.FirewallRules = []models.FirewallRule{}
	}
	writeJSON(w, 200, c.FirewallRules)
}

func (s *Server) hRuleAdd(w http.ResponseWriter, r *http.Request) {
	var ru models.FirewallRule
	if err := decodeBody(r, &ru); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if ru.ID == "" {
		ru.ID = fmt.Sprintf("rule%d", time.Now().UnixNano()%1000000)
	}
	c := s.effectiveConfig()
	for _, x := range c.FirewallRules {
		if x.ID == ru.ID {
			writeErr(w, 409, "rule exists")
			return
		}
	}
	c.FirewallRules = append(c.FirewallRules, ru)
	s.applyNewConfig(w, r, c, applyOpts{message: "firewall rule " + ru.ID, created: true,
		confirm: confirmFrom(r), object: "firewall_rule " + ru.ID}, "")
}

func (s *Server) hRulePatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var ru models.FirewallRule
	if err := decodeBody(r, &ru); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	c := s.effectiveConfig()
	for i := range c.FirewallRules {
		if c.FirewallRules[i].ID == id {
			ru.ID = id
			c.FirewallRules[i] = ru
			s.applyNewConfig(w, r, c, applyOpts{message: "firewall rule updated " + id,
				confirm: confirmFrom(r), object: "firewall_rule " + id}, "")
			return
		}
	}
	writeErr(w, 404, "rule not found")
}

func (s *Server) hRuleDelete(w http.ResponseWriter, r *http.Request) {
	s.deleteInConfig(w, r, func(c *models.Config) bool {
		for i := range c.FirewallRules {
			if c.FirewallRules[i].ID == r.PathValue("id") {
				c.FirewallRules = append(c.FirewallRules[:i], c.FirewallRules[i+1:]...)
				return true
			}
		}
		return false
	}, "firewall_rule")
}

func (s *Server) deleteInConfig(w http.ResponseWriter, r *http.Request, del func(*models.Config) bool, kind string) {
	c := s.effectiveConfig()
	if !del(&c) {
		writeErr(w, 404, kind+" not found")
		return
	}
	s.applyNewConfig(w, r, c, applyOpts{message: kind + " deleted",
		confirm: confirmFrom(r), object: kind + " " + r.PathValue("id")}, "")
}

// --- port forwards ---

func (s *Server) hPFList(w http.ResponseWriter, r *http.Request) {
	c := s.effectiveConfig()
	if c.PortForwards == nil {
		c.PortForwards = []models.PortForward{}
	}
	writeJSON(w, 200, c.PortForwards)
}

func (s *Server) hPFAdd(w http.ResponseWriter, r *http.Request) {
	var pf models.PortForward
	if err := decodeBody(r, &pf); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if pf.ID == "" {
		pf.ID = fmt.Sprintf("pf%d", time.Now().UnixNano()%1000000)
	}
	c := s.effectiveConfig()
	c.PortForwards = append(c.PortForwards, pf)
	s.applyNewConfig(w, r, c, applyOpts{message: "port forward " + pf.ID, created: true,
		confirm: confirmFrom(r), object: "port_forward " + pf.ID}, "")
}

func (s *Server) hPFPatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var pf models.PortForward
	if err := decodeBody(r, &pf); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	c := s.effectiveConfig()
	for i := range c.PortForwards {
		if c.PortForwards[i].ID == id {
			pf.ID = id
			c.PortForwards[i] = pf
			s.applyNewConfig(w, r, c, applyOpts{message: "port forward updated " + id,
				confirm: confirmFrom(r), object: "port_forward " + id}, "")
			return
		}
	}
	writeErr(w, 404, "port forward not found")
}

func (s *Server) hPFDelete(w http.ResponseWriter, r *http.Request) {
	s.deleteInConfig(w, r, func(c *models.Config) bool {
		for i := range c.PortForwards {
			if c.PortForwards[i].ID == r.PathValue("id") {
				c.PortForwards = append(c.PortForwards[:i], c.PortForwards[i+1:]...)
				return true
			}
		}
		return false
	}, "port_forward")
}

// --- wireguard ---

func (s *Server) hWGTunnels(w http.ResponseWriter, r *http.Request) {
	c := s.effectiveConfig()
	out := []models.WireGuardTunnel{}
	for _, t := range c.WireGuard {
		out = append(out, wireguard.Mask(t))
	}
	writeJSON(w, 200, out)
}

func (s *Server) hWGAdd(w http.ResponseWriter, r *http.Request) {
	var t models.WireGuardTunnel
	if err := decodeBody(r, &t); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if t.Name == "" {
		writeErr(w, 400, "name required")
		return
	}
	c := s.effectiveConfig()
	for i := range c.WireGuard {
		if c.WireGuard[i].Name == t.Name { // replace (upsert keeps id/name)
			if t.PrivateKey == "" || t.PrivateKey == "***" {
				t.PrivateKey = c.WireGuard[i].PrivateKey
			}
			c.WireGuard[i] = t
			s.applyNewConfig(w, r, c, applyOpts{message: "wireguard tunnel updated " + t.Name,
				confirm: confirmFrom(r), object: "wireguard " + t.Name}, "")
			return
		}
	}
	c.WireGuard = append(c.WireGuard, t)
	s.applyNewConfig(w, r, c, applyOpts{message: "wireguard tunnel " + t.Name, created: true,
		confirm: confirmFrom(r), object: "wireguard " + t.Name}, "")
}

func (s *Server) hWGDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.deleteInConfig(w, r, func(c *models.Config) bool {
		for i := range c.WireGuard {
			if c.WireGuard[i].Name == name {
				c.WireGuard = append(c.WireGuard[:i], c.WireGuard[i+1:]...)
				return true
			}
		}
		return false
	}, "wireguard")
}

// --- devices / wan / leases / events / audit ---

func (s *Server) syncAliases() {
	s.monitor.SetAliases(s.st.DeviceAliases())
}

func (s *Server) hDevices(w http.ResponseWriter, r *http.Request) {
	devs := s.monitor.Devices(s.effectiveConfig())
	if devs == nil {
		devs = []monitor.Device{}
	}
	writeJSON(w, 200, devs)
}

func (s *Server) hDeviceName(w http.ResponseWriter, r *http.Request) {
	mac := strings.ToLower(r.PathValue("mac"))
	var b struct {
		Name string `json:"name"`
	}
	if err := decodeBody(r, &b); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if err := s.st.SetDeviceAlias(mac, b.Name); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.syncAliases()
	s.audit(r, "device.name", mac, "ok")
	writeJSON(w, 200, map[string]string{"mac": mac, "name": b.Name})
}

func (s *Server) hWANStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.monitor.WANStatus(s.effectiveConfig()))
}

func (s *Server) hLeases(w http.ResponseWriter, r *http.Request) {
	out := []state.Lease{}
	if ls, ok := s.opt.Src.(monitor.LeaseSource); ok {
		out = ls.Leases()
	} else if ls, ok := s.opt.Exec.(monitor.LeaseSource); ok {
		out = ls.Leases()
	}
	writeJSON(w, 200, out)
}

func (s *Server) hEvents(w http.ResponseWriter, r *http.Request) {
	since := uint64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		since, _ = strconv.ParseUint(v, 10, 64)
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	evs := s.st.Events(since)
	if limit > 0 && len(evs) > limit {
		evs = evs[len(evs)-limit:] // keep the newest events
	}
	if evs == nil {
		evs = []store.Event{}
	}
	writeJSON(w, 200, evs)
}

func (s *Server) hAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	writeJSON(w, 200, s.st.AuditLog(limit))
}

// --- config endpoints ---

func (s *Server) hConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.effectiveConfig())
}

func (s *Server) hConfigPut(w http.ResponseWriter, r *http.Request) {
	var c models.Config
	if err := decodeBody(r, &c); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	config.ApplyDefaults(&c)
	s.applyNewConfig(w, r, c, applyOpts{message: "full configuration replaced",
		confirm: confirmFrom(r), object: "config"}, "")
}

func (s *Server) hConfigValidate(w http.ResponseWriter, r *http.Request) {
	var c models.Config
	if err := decodeBody(r, &c); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	config.ApplyDefaults(&c)
	errs := models.Validate(c)
	if len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"valid": false, "fields": errs})
		return
	}
	writeJSON(w, 200, map[string]any{"valid": true})
}

func (s *Server) hRevisions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.st.Revisions())
}

func (s *Server) hRevisionGet(w http.ResponseWriter, r *http.Request) {
	rev, _ := strconv.Atoi(r.PathValue("rev"))
	c, meta, err := s.st.Revision(rev)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"meta": meta, "config": c})
}

func (s *Server) hRevisionRestore(w http.ResponseWriter, r *http.Request) {
	rev, _ := strconv.Atoi(r.PathValue("rev"))
	c, meta, err := s.st.Revision(rev)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	s.applyNewConfig(w, r, c, applyOpts{
		message: fmt.Sprintf("restored from revision %d (%s)", rev, meta.Message),
		confirm: confirmFrom(r), object: fmt.Sprintf("revision %d", rev)}, "")
}

// --- transactions (§26) ---

func (s *Server) hTxnBegin(w http.ResponseWriter, r *http.Request) {
	t := &transaction{id: fmt.Sprintf("txn_%d", time.Now().UnixNano()),
		draft: s.effectiveConfig()}
	s.mu.Lock()
	s.txns[t.id] = t
	s.mu.Unlock()
	writeJSON(w, 201, map[string]any{"id": t.id, "config": t.draft})
}

func (s *Server) getTxn(w http.ResponseWriter, r *http.Request) (*transaction, bool) {
	s.mu.Lock()
	t := s.txns[r.PathValue("id")]
	s.mu.Unlock()
	if t == nil {
		writeErr(w, 404, "unknown transaction")
		return nil, false
	}
	return t, true
}

func (s *Server) hTxnGet(w http.ResponseWriter, r *http.Request) {
	t, ok := s.getTxn(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"id": t.id, "config": t.draft})
}

func (s *Server) hTxnConfig(w http.ResponseWriter, r *http.Request) {
	t, ok := s.getTxn(w, r)
	if !ok {
		return
	}
	var c models.Config
	if err := decodeBody(r, &c); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	config.ApplyDefaults(&c)
	if errs := models.Validate(c); len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"error": "invalid configuration", "fields": errs})
		return
	}
	t.draft = c
	writeJSON(w, 200, map[string]any{"id": t.id, "config": t.draft})
}

func (s *Server) hTxnValidate(w http.ResponseWriter, r *http.Request) {
	t, ok := s.getTxn(w, r)
	if !ok {
		return
	}
	if errs := models.Validate(t.draft); len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"valid": false, "fields": errs})
		return
	}
	writeJSON(w, 200, map[string]any{"valid": true})
}

func (s *Server) hTxnApply(w http.ResponseWriter, r *http.Request) {
	t, ok := s.getTxn(w, r)
	if !ok {
		return
	}
	t.base = s.effectiveConfig()
	s.applyNewConfig(w, r, t.draft, applyOpts{message: "transaction " + t.id,
		confirm: confirmFrom(r), object: "transaction " + t.id}, t.id)
}

func (s *Server) hTxnCommit(w http.ResponseWriter, r *http.Request) {
	t, ok := s.getTxn(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	p := s.pend
	s.mu.Unlock()
	if p == nil || p.txnID != t.id {
		writeErr(w, 409, "transaction is not in pending state (apply first)")
		return
	}
	s.commitPending(w, r, p.token)
	s.mu.Lock()
	delete(s.txns, t.id)
	s.mu.Unlock()
}

func (s *Server) hTxnRollback(w http.ResponseWriter, r *http.Request) {
	t, ok := s.getTxn(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	pendingForTxn := s.pend != nil && s.pend.txnID == t.id
	delete(s.txns, t.id)
	s.mu.Unlock()
	if pendingForTxn {
		s.rollbackPending(w, r)
		return
	}
	if len(t.base.WANs) > 0 {
		// transaction was applied immediately: restore its base config
		s.applyNewConfig(w, r, t.base, applyOpts{message: "transaction " + t.id + " rolled back",
			object: "transaction " + t.id}, "")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "discarded"})
}

// --- metrics (§42) ---

func (s *Server) hMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	c := s.effectiveConfig()
	fmt.Fprintf(&b, "# routerd %s\n", s.opt.Version)
	fmt.Fprintf(&b, "router_up 1\n")
	if a, err := reconcile.Observe(r.Context(), s.opt.Exec); err == nil {
		for _, l := range a.Links {
			n := strconv.Quote(l.Name)
			fmt.Fprintf(&b, "router_interface_rx_bytes{interface=%s} %d\n", n, l.Stats.RxBytes)
			fmt.Fprintf(&b, "router_interface_tx_bytes{interface=%s} %d\n", n, l.Stats.TxBytes)
			fmt.Fprintf(&b, "router_interface_rx_packets{interface=%s} %d\n", n, l.Stats.RxPackets)
			fmt.Fprintf(&b, "router_interface_tx_packets{interface=%s} %d\n", n, l.Stats.TxPackets)
			up := 0
			if l.Up {
				up = 1
			}
			fmt.Fprintf(&b, "router_interface_up{interface=%s} %d\n", n, up)
		}
	}
	for _, st := range s.monitor.WANStatus(c) {
		up := 0
		if st.Up {
			up = 1
		}
		fmt.Fprintf(&b, "router_wan_up{interface=%q} %d\n", st.Interface, up)
	}
	leases := 0
	if ls, ok := s.opt.Src.(monitor.LeaseSource); ok {
		leases = len(ls.Leases())
	} else if ls, ok := s.opt.Exec.(monitor.LeaseSource); ok {
		leases = len(ls.Leases())
	}
	fmt.Fprintf(&b, "router_dhcp_active_leases %d\n", leases)
	fmt.Fprintf(&b, "router_config_revision %d\n", s.currentRev())
	write(w, b.String())
}

func (s *Server) currentRev() int {
	_, meta, _ := s.st.Current()
	return meta.Rev
}

func write(w http.ResponseWriter, s string) { fmt.Fprint(w, s) }

// SetLatency is a test hook placeholder (no-op in production).
func (s *Server) SetLatency(d time.Duration) {}

var _ = errors.New

// Engine exposes the reconciliation engine.
func (s *Server) Engine() *reconcile.Engine { return s.engine }

// Committed returns the persisted (committed) configuration.
func (s *Server) Committed() (models.Config, store.RevMeta, error) {
	return s.st.Current()
}

// Event records a system event.
func (s *Server) Event(kind, detail string) { s.event(kind, detail) }

// ListenAndServeHTTP serves plain HTTP (development).
func (s *Server) ListenAndServeHTTP(addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// ReconcileNow re-converges the live system toward the effective config
// (used by the periodic drift-repair loop).
func (s *Server) ReconcileNow() {
	c := s.effectiveConfig()
	d, err := reconcile.Build(c)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := s.engine.Apply(ctx, d); err != nil {
		s.event("reconcile.drift", err.Error())
	}
}

// hServices reports status of system services routerd manages.
func (s *Server) hServices(w http.ResponseWriter, r *http.Request) {
	c := s.effectiveConfig()
	type svc struct {
		Name    string `json:"name"`
		Managed bool   `json:"managed"`
		Status  string `json:"status"`
		Detail  string `json:"detail,omitempty"`
	}
	out := []svc{}
	_, present := s.opt.Exec.File(dhcp.ConfPathFor())
	name := dhcp.ServiceName
	status := "unmanaged"
	if present {
		status = s.serviceActive(name)
	}
	out = append(out, svc{Name: name, Managed: present, Status: status})
	for _, t := range c.WireGuard {
		st := "unknown"
		detail := ""
		if outB, err := s.opt.Exec.Run(r.Context(), nil, "wg", "show", t.Name); err == nil {
			st = "up"
			detail = strings.SplitN(strings.TrimSpace(string(outB)), "\n", 2)[0]
		} else {
			st, detail = "down", errText(err)
		}
		out = append(out, svc{Name: "wireguard:" + t.Name, Managed: true,
			Status: st, Detail: detail})
	}
	writeJSON(w, 200, out)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// hDHCPStatus reports the authoritative dnsmasq state.
func (s *Server) hDHCPStatus(w http.ResponseWriter, r *http.Request) {
	c := s.effectiveConfig()
	conf, present := s.opt.Exec.File(dhcp.ConfPathFor())
	want, _ := dhcp.GenerateDnsmasqConf(c)
	inSync := present && string(conf) == want
	leases := 0
	if lb, ok := s.opt.Exec.File(dhcp.LeaseFilePath()); ok {
		for _, line := range strings.Split(string(lb), "\n") {
			if len(strings.Fields(line)) >= 5 {
				leases++
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"enabled": len(want) > 0, "conf_path": dhcp.ConfPathFor(),
		"conf_present": present, "in_sync": inSync,
		"service": s.serviceActive(dhcp.ServiceName), "active_leases": leases,
	})
}

func (s *Server) serviceActive(name string) string {
	out, err := s.opt.Exec.Run(context.Background(), nil, "systemctl", "is-active", name)
	if err != nil {
		return "inactive"
	}
	return strings.TrimSpace(string(out))
}
