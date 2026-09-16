// cmd/routerd is the privileged management daemon (design section 6).
//
// Data-plane note: Linux performs all packet forwarding; routerd only
// reconciles kernel state from the declarative configuration and serves
// the management API. If routerd dies, routing/firewall persist (section 46).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"router/internal/api"
	"router/internal/config"
	"router/internal/platform"
	"router/internal/reconcile"
	"router/internal/store"
)

func main() {
	var (
		dataDir    = flag.String("data-dir", "/var/lib/routerd", "persistent state directory")
		listen     = flag.String("listen", ":8443", "management API listen address")
		backend    = flag.String("backend", "linux", "executor backend: linux|fake")
		ifaces     = flag.String("ifaces", "eth0,eth1,eth2", "physical interfaces for the fake backend")
		bootstrap  = flag.String("config", "", "optional YAML/JSON file seeding the initial configuration")
		adminPw    = flag.String("admin-password", "", "initial admin password (generated when empty)")
		cert       = flag.String("tls-cert", "", "TLS certificate (self-signed generated when empty)")
		key        = flag.String("tls-key", "", "TLS private key")
		plain      = flag.Bool("plain-http", false, "serve plain HTTP (development only)")
		reconcileI = flag.Duration("reconcile-interval", 5*time.Minute, "periodic drift-repair interval (0 disables)")
	)
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("routerd: %v", err)
	}

	var ex platform.Executor
	var src any
	switch *backend {
	case "fake":
		f := platform.NewFake(strings.Split(*ifaces, ","))
		ex, src = f, f
		log.Printf("routerd: SIMULATED linux backend (interfaces %v) - no real packets are forwarded",
			strings.Split(*ifaces, ","))
	case "linux":
		ex = platform.NewLinux(*dataDir)
	default:
		log.Fatalf("routerd: unknown backend %q", *backend)
	}

	if *bootstrap != "" {
		seedFrom(*dataDir, *bootstrap)
	}

	srv, err := api.New(api.Options{
		DataDir: *dataDir, Exec: ex, Src: src, AdminPassword: *adminPw,
	})
	if err != nil {
		log.Fatalf("routerd: %v", err)
	}

	// Boot sequence (section 47): load config, inspect actual state, reconcile.
	if c, _, err := srv.Committed(); err == nil {
		if d, berr := reconcile.Build(c); berr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			if _, aerr := srv.Engine().Apply(ctx, d); aerr != nil {
				log.Printf("routerd: initial reconciliation: %v", aerr)
				srv.Event("reconcile.failed", aerr.Error())
			} else {
				log.Printf("routerd: desired state reconciled")
			}
			cancel()
		} else {
			log.Printf("routerd: configuration invalid: %v", berr)
		}
	}

	// Periodic drift repair (section 59: reconciliation is continuous).
	stop := make(chan struct{})
	if *reconcileI > 0 {
		go func() {
			t := time.NewTicker(*reconcileI)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					srv.ReconcileNow()
				case <-stop:
					return
				}
			}
		}()
	}

	srv.Event("daemon.start", *listen)
	log.Printf("routerd %s listening on %s (backend=%s, data=%s)", api.Version, *listen, *backend, *dataDir)

	errCh := make(chan error, 1)
	go func() {
		if *plain {
			errCh <- srv.ListenAndServeHTTP(*listen)
		} else {
			errCh <- srv.ListenAndServe(*listen, *cert, *key)
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("routerd: %v", err)
		}
	case <-sig:
		log.Printf("routerd: shutting down")
		srv.Event("daemon.stop", "signal")
		close(stop)
	}
}

func seedFrom(dataDir, path string) {
	cfgPath := filepath.Join(dataDir, "config.json")
	if _, err := os.Stat(cfgPath); err == nil {
		return // store already initialized
	}
	c, err := config.LoadFile(path)
	if err != nil {
		log.Fatalf("routerd: bootstrap config: %v", err)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		log.Fatalf("routerd: %v", err)
	}
	defer st.Close()
	if err := st.Save(c, "system", "bootstrap from "+path); err != nil {
		log.Fatalf("routerd: %v", err)
	}
	log.Printf("routerd: seeded configuration from %s", path)
}
