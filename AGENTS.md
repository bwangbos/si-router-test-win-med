# AGENTS.md

## Non-negotiable architecture rules

- **Config is the single source of truth.** Everything flows `models.Config → validate → reconcile → store revision`. Kernel state is only ever observed to converge toward config — never import kernel state into config. Exceptions (observation-only): WAN DHCP-acquired addresses, leases, ARP/NDP neighbors, device aliases.
- **One write path.** Only the reconcile engine touches the data plane; UI, CLI and scripts are peers over the same authenticated `/api/v1` API. Any new feature must fit this pipeline — no direct-command side doors.
- **Every Executor command must be simulated by `platform.Fake`.** Tests run as plain user on Windows, never root. When the planner emits new tool syntax, extend Fake to match real-tool behavior (Fake must stay high-fidelity; see implicit-kind `clsact` fix 722fc2e).
- **TDD.** Regression test with every real-world bug fix.

## Commit-window semantics (§25/§26)

- Mutations accept `?confirm_seconds=N`: apply is live but pending; unconfirmed → auto-rollback. There is exactly **one global pending window**; any immediate apply must disarm a stale pending timer (race fixed; test `TestPlainApplyCancelsStalePending`).
- During the window, APIs must serve the **pending** config (`effectiveConfig()`), not the committed one.
- Transactions keep a server-side draft; `apply` forces a confirm window.

## Engine schema (be careful)

`reconcile.Operation{Reconciler, Desc, Commands}` / `Command{Argv, Stdin, WritePath, WriteData, IgnoreErrors}` — the original schema. Large full-file rewrites of engine.go have silently vanished; prefer targeted edits.

## Real-world quirks encoded (do not "simplify" away)

- Routes: iproute2 `comment` unsupported → provenance file `dataDir/routes.mgmt.json`; delete stale routerd-owned routes only if present (idempotent).
- nft: `list ruleset` strips `#` comments → drift hash lives in the input chain's `comment` property (`routerd-sha:…`). Empty zone sets must be `set x { type ifname; }` (bare, no `elements = { }`); rules referencing zones without networks need an empty set declared.
- dnsmasq: driven via `--conf-file=` only (never the distro unit/conf-dir); dedicated unit `routerd-dnsmasq.service`; `except-interface=lo` (stub resolvers own :53 on lo); flags `--no-confdir` and `leasefile-ro=no` do not exist.
- API JSON: list endpoints must return `[]`, never Go-nil `null`.

## Lockout safety invariants

Generated config may never: put DHCP/DNS on WAN, hijack the WAN default route (router routes carry `metric 1000`), or destroy a WAN address. Deleting a network must also clean bridge, dnsmasq pool, nft sets.

## Dev environment

- Windows host, git-bash; Go toolchain installed but not on PATH. `gofmt -w` before commit.
- Real-Linux checks: cross-compile `GOOS=linux CGO_ENABLED=0`, run as root in a throwaway Linux VM/container; git-bash mangles `/mnt/` paths — prefix `MSYS_NO_PATHCONV=1`.
- CLI bool flags must not consume the next token (`boolFlags` table in `routerctl`).
- Local demo: `routerd --backend fake --plain-http` with a throwaway data dir and dev password. Screenshots: playwright-core + Edge-headless script → `docs/screenshots/`.

## Security posture

- Read-only sessions must see no secrets and get no mutations; WG private keys are write-only on `/wireguard` endpoints (admin-only full `/config` GET still exposes them — keep that in mind before loosening).
- Static UI assets are public by design (no secrets); all authority lives in API auth.
