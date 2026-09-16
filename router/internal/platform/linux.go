package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"router/internal/state"
)

// Linux is the production Executor: it invokes iproute2/nft/tc/wg by
// explicit argv (never a shell, design section 36) and manages service
// state files on the real filesystem.
type Linux struct {
	dataDir   string
	leaseFile string
}

// NewLinux creates the production executor. dataDir hosts runtime artifacts.
func NewLinux(dataDir string) *Linux {
	return &Linux{dataDir: dataDir, leaseFile: "/var/lib/misc/dnsmasq.leases"}
}

// SetLeaseFile overrides the dnsmasq lease file location.
func (l *Linux) SetLeaseFile(p string) { l.leaseFile = p }

// allowedTools restricts which binaries may be executed (defense in depth).
var allowedTools = map[string]bool{
	"ip": true, "nft": true, "tc": true, "wg": true, "systemctl": true,
}

// Run implements Executor.
func (l *Linux) Run(ctx context.Context, stdin []byte, argv ...string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("platform: empty command")
	}
	if !allowedTools[argv[0]] {
		return nil, fmt.Errorf("platform: command %q not allowed", argv[0])
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = err.Error()
		}
		return out, fmt.Errorf("%s: %s", strings.Join(argv, " "), msg)
	}
	return out, nil
}

// WriteFile writes path atomically, creating parents.
func (l *Linux) WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".routerd.tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// File reads a file (for config drift detection).
func (l *Linux) File(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Leases implements monitor.LeaseSource by parsing the dnsmasq lease file.
func (l *Linux) Leases() []state.Lease {
	b, err := os.ReadFile(l.leaseFile)
	if err != nil {
		return nil
	}
	now := time.Now()
	var out []state.Lease
	for _, le := range state.ParseLeases(b) {
		if le.Expiry.After(now) {
			out = append(out, le)
		}
	}
	return out
}

var _ Executor = (*Linux)(nil)
