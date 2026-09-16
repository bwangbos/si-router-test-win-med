#!/usr/bin/env bash
# si-router installer: builds and installs the routerd daemon (systemd unit)
# and the routerctl CLI. Run as root:  sudo bash install.sh [options]
#
# Options:
#   --repo URL        git repository to build from   (default: GitHub origin)
#   --ref REF         branch/tag/commit              (default: main)
#   --from DIR        install prebuilt routerd-linux/routerctl-linux from DIR
#                     instead of building (skips git and Go entirely)
#   --bin-dir DIR     binary install dir             (default: /usr/local/bin)
#   --data-dir DIR    routerd state directory        (default: /var/lib/routerd)
#   --listen ADDR     management API listen address  (default: 0.0.0.0:8443)
#   --no-enable       install + start but do not enable at boot
#   --uninstall       stop and remove service + binaries (state dir kept)
#   --purge           with --uninstall, also remove the state directory
set -euo pipefail

REPO=${REPO:-https://github.com/bwangbos/si-router-test-win-med}
REF=${REF:-main}
BIN_DIR=/usr/local/bin
DATA_DIR=/var/lib/routerd
LISTEN=0.0.0.0:8443
ENABLE=1
FROM=""
UNINSTALL=0
PURGE=0
UNIT=/etc/systemd/system/routerd.service

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO=$2; shift 2;;
    --ref) REF=$2; shift 2;;
    --from) FROM=$2; shift 2;;
    --bin-dir) BIN_DIR=$2; shift 2;;
    --data-dir) DATA_DIR=$2; shift 2;;
    --listen) LISTEN=$2; shift 2;;
    --no-enable) ENABLE=0; shift;;
    --uninstall) UNINSTALL=1; shift;;
    --purge) PURGE=1; shift;;
    -h|--help) sed -n '2,17p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

if [ "$(id -u)" != 0 ]; then
  echo "must run as root (sudo)" >&2
  exit 1
fi

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now routerd 2>/dev/null || true
  systemctl disable --now routerd-dnsmasq 2>/dev/null || true
  rm -f "$UNIT" /etc/systemd/system/routerd-dnsmasq.service
  rm -f "$BIN_DIR/routerd" "$BIN_DIR/routerctl"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$DATA_DIR" /etc/dnsmasq.d/router.conf /var/lib/misc/dnsmasq.leases
  fi
  systemctl daemon-reload
  echo "si-router uninstalled (state dir kept unless --purge)"
  exit 0
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

SRC=""
cleanup() { [ -n "$SRC" ] && [ -d "$SRC" ] && rm -rf "$SRC"; }
trap cleanup EXIT

if [ -n "$FROM" ]; then
  need install
  for b in routerd-linux routerctl-linux; do
    [ -x "$FROM/$b" ] || { echo "prebuilt binary not found: $FROM/$b" >&2; exit 1; }
  done
  install -m 0755 "$FROM/routerd-linux" "$BIN_DIR/routerd"
  install -m 0755 "$FROM/routerctl-linux" "$BIN_DIR/routerctl"
else
  need git
  SRC=$(mktemp -d)
  git clone --quiet --depth 1 --branch "$REF" "$REPO" "$SRC"
  GO=$(command -v go || true)
  if [ -z "$GO" ] && [ -x /usr/local/go/bin/go ]; then GO=/usr/local/go/bin/go; fi
  if [ -z "$GO" ]; then
    echo "Go not found — downloading toolchain to /usr/local/go" >&2
    need curl; need tar
    arch=$(uname -m); case $arch in x86_64) arch=amd64;; aarch64) arch=arm64;;
      *) echo "unsupported arch: $arch" >&2; exit 1;; esac
    gv=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    curl -fsSL "https://go.dev/dl/${gv}.linux-${arch}.tar.gz" | tar -C /usr/local -xz
    GO=/usr/local/go/bin/go
  fi
  ver=$("$GO" version | awk '{print $3}' | sed 's/go//;s/\./ /g')
  maj=$(echo "$ver" | awk '{print $1}'); min=$(echo "$ver" | awk '{print $2+0}')
  if [ "$maj" -lt 1 ] || { [ "$maj" -eq 1 ] && [ "$min" -lt 22 ]; }; then
    echo "go >= 1.22 required (found $($GO version))" >&2; exit 1
  fi
  need install
  (cd "$SRC/router" && CGO_ENABLED=0 "$GO" build -trimpath -o "$SRC/routerd" ./cmd/routerd \
    && CGO_ENABLED=0 "$GO" build -trimpath -o "$SRC/routerctl" ./cmd/routerctl)
  install -m 0755 "$SRC/routerd" "$BIN_DIR/routerd"
  install -m 0755 "$SRC/routerctl" "$BIN_DIR/routerctl"
fi

mkdir -p "$DATA_DIR"
if ! command -v dnsmasq >/dev/null 2>&1; then
  echo "dnsmasq not found (required for the DHCP/DNS service)"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsmasq
    systemctl disable --now dnsmasq 2>/dev/null || true  # routerd uses its own unit
  else
    echo "install dnsmasq manually, then restart routerd" >&2
  fi
fi
cat > "$UNIT" <<EOF
[Unit]
Description=si-router routerd (router control plane)
Documentation=https://github.com/bwangbos/si-router-test-win-med
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN_DIR/routerd --backend linux --data-dir $DATA_DIR --listen $LISTEN
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
if [ "$ENABLE" = 1 ]; then
  systemctl enable --now routerd
else
  systemctl restart routerd
fi
sleep 1
systemctl --no-pager -n 0 status routerd || true

echo
echo "routerd listening on https://$LISTEN/ (self-signed certificate on first start)"
pwf=$DATA_DIR/initial-admin-password
if [ -f "$pwf" ]; then
  echo "initial admin password: $(cat "$pwf")  (stored 0600 in $pwf — delete after first login)"
fi
echo "then:  routerctl --insecure status"
