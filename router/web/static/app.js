/* routerd management UI — dependency-free SPA over /api/v1 (same API as routerctl) */
"use strict";

/* ---------- helpers ---------- */
const $ = s => document.querySelector(s);
const F = (f, n) => f.elements.namedItem(n); // avoid HTMLFormElement property collisions (.name/.action)
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtBytes = n => { n = Number(n) || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + " " + u[i]; };
const fmtDur = sec => { sec = Number(sec) || 0; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return (d ? d + "d " : "") + h + "h " + m + "m"; };
const ago = t => { const s = (Date.now() - Date.parse(t)) / 1000; if (s < 90) return Math.round(s) + "s ago"; if (s < 5400) return Math.round(s / 60) + "m ago"; if (s < 172800) return Math.round(s / 3600) + "h ago"; return new Date(t).toLocaleDateString(); };
const arr = x => Array.isArray(x) ? x : [];
const pill = (txt, cls) => `<span class="pill ${cls || "dim"}">${esc(txt)}</span>`;
const pcls = s => { s = String(s).toLowerCase(); return /^(ok|healthy|up|active|enabled|committed)$/.test(s) ? "ok" : /^(warn|degraded|pending|drifted)$/.test(s) ? "warn" : /^(err|error|critical|unhealthy|down|fail|expired)$/.test(s) ? "err" : "dim"; };
const yn = b => b ? pill("yes", "ok") : pill("no");
const toast = (msg, cls = "") => { const d = document.createElement("div"); d.className = "toast " + cls; d.innerHTML = msg; $("#toasts").append(d); setTimeout(() => d.remove(), 6000); };
const card = (title, inner) => `<div class=card><h3>${esc(title)}</h3>${inner}</div>`;
const kv = pairs => `<div class=kv>` + pairs.map(([k, v]) => `<b>${esc(k)}</b><span>${v}</span>`).join("") + `</div>`;

const S = { token: localStorage.getItem("router_token") || "", role: "", user: "", cfg: {}, pending: null, txn: "", view: "", timers: [] };

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (S.token) opt.headers.Authorization = "Bearer " + S.token;
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch("/api/v1" + path, opt);
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  if (r.status === 401 && !path.startsWith("/auth/login")) { logout(false); throw new Error("session expired"); }
  if (!r.ok) throw new Error((data && (data.error || data.detail)) || ("HTTP " + r.status));
  return data || {};
}
const confQS = () => (+$("#confirmSel").value > 0) ? "?confirm_seconds=" + $("#confirmSel").value : "";
const mayWrite = () => S.role === "admin";
const windowLabel = () => $("#confirmSel").selectedOptions[0].text;

/* handles the response of any mutating call (may open a confirm window) */
function applied(res) {
  if (res.status === "pending") {
    toast("Change applied in a <b>confirmed-commit window</b> — confirm below or it auto-rolls back.", "warn");
    pollPending();
  } else toast("Applied &amp; committed.", "ok");
  loadCfg().then(render, render);
}
const guard = fn => async el => {
  try { await fn(el); } catch (e) { toast(esc(e.message), "err"); }
};

/* ---------- shared state ---------- */
async function loadCfg() { S.cfg = await api("GET", "/config"); }
async function pollPending() {
  try {
    const p = await api("GET", "/config/pending");
    S.pending = p.pending || null;
  } catch { S.pending = null; }
  const b = $("#banner");
  if (!S.pending) { b.innerHTML = ""; return; }
  const left = Math.max(0, Math.round((Date.parse(S.pending.expires) - Date.now()) / 1000));
  b.innerHTML = `<div class="notice">⏳ Unconfirmed ${S.pending.txn ? "transaction <b class=mono>" + esc(S.pending.txn) + "</b>" : "change"} — auto-rollback in <b>${left}s</b>.
    <span class=spacer></span>
    ${mayWrite() ? `<button data-act=commit class="mini">Confirm &amp; keep</button>
    <button data-act=revert class="mini danger">Revert now</button>` : ""}</div>`;
}
async function pollTop() {
  try {
    const sys = await api("GET", "/system");
    $("#hostline").innerHTML = `<b>${esc(sys.hostname)}</b> · routerd ${esc(sys.version)} · rev ${sys.revision} · up ${fmtDur(sys.uptime_seconds)}`;
    const hp = $("#healthpill");
    hp.textContent = sys.health;
    hp.className = "pill " + pcls(sys.health);
  } catch { /* handled by api()'s 401 path */ }
}

/* ---------- views ---------- */
const VIEWS = {
  dashboard: ["Dashboard", viewDashboard], internet: ["Internet", viewInternet],
  networks: ["Networks", viewNetworks], devices: ["Devices", viewDevices],
  firewall: ["Firewall", viewFirewall], portfwd: ["Port Forwards", viewPF],
  vpn: ["VPN (WireGuard)", viewVPN], traffic: ["Traffic", viewTraffic],
  system: ["System", viewSystem], logs: ["Logs", viewLogs],
};

async function viewDashboard(v) {
  const [wan, ifaces, svcs, dhcp, evs, health] = await Promise.all([
    api("GET", "/wan/status"), api("GET", "/interfaces"), api("GET", "/services"),
    api("GET", "/config/dhcp"), api("GET", "/events?limit=8"), api("GET", "/health")]);
  const wanInner = arr(wan).length ? wan.map(w => `<div class=row>${w.up ? pill("up", "ok") : pill("down", "err")}
      <b>${esc(w.interface)}</b> <span class=mono>${esc(w.address || "no address")}</span>
      <span class="muted small">gw ${esc(w.gateway || "—")} · rx ${fmtBytes(w.stats?.rx_bytes)} tx ${fmtBytes(w.stats?.tx_bytes)}</span></div>`).join("") : "<span class=muted>no WAN defined</span>";
  v.innerHTML = `<h1>Dashboard</h1>
  <div class=cards>
    ${card("Internet", wanInner)}
    ${card("Health", kv(arr(health.checks).map(c => [c.name, pill(c.status, pcls(c.status)) + ` <span class="muted small">${esc(c.detail || "")}</span>`])))}
    ${card("DHCP server", kv([["service", pill(dhcp.service || "n/a", pcls(dhcp.service))], ["leases", dhcp.active_leases ?? "—"], ["config", dhcp.in_sync ? pill("in sync", "ok") : pill("drifted", "warn")], ["conf", `<span class="mono small">${esc(dhcp.conf_path || "—")}</span>`]]))}
    ${card("Services", arr(svcs).map(s => `<div class=row>${pill(s.status, pcls(s.status))} <b>${esc(s.name)}</b> <span class="muted small">${esc(s.detail || "")}</span></div>`).join("") || "<span class=muted>none</span>")}
  </div>
  <h2>Interfaces</h2>
  <table><tr><th>Name</th><th>Type</th><th>State</th><th>MTU</th><th>Master</th><th>Addresses</th><th>Network</th><th>Rx / Tx</th></tr>
  ${arr(ifaces).map(i => `<tr><td class=mono><b>${esc(i.name)}</b></td><td>${esc(i.type)}</td>
    <td>${i.up ? pill("up", "ok") : pill("down")}</td><td>${i.mtu || ""}</td>
    <td class=mono>${esc(i.master || "")}</td><td class=mono>${arr(i.addrs).map(esc).join("<br>")}</td>
    <td>${i.network ? pill(i.network, "ok") : ""}</td><td class="muted small mono">${fmtBytes(i.stats?.rx_bytes)} / ${fmtBytes(i.stats?.tx_bytes)}</td></tr>`).join("")}
  </table>
  <h2>Recent events</h2>
  <table>${arr(evs).slice().reverse().reverse().map(e => `<tr><td class="muted small" style=width:90px>${ago(e.time)}</td><td class=mono>${esc(e.kind)}</td><td class=muted>${esc(e.detail || "")}</td></tr>`).join("") || "<tr><td class=muted>no events yet</td></tr>"}</table>`;
}

async function viewInternet(v) {
  const wan = await api("GET", "/wan/status");
  const st = Object.fromEntries(arr(wan).map(w => [w.interface, w]));
  v.innerHTML = `<h1>Internet</h1>` + arr(S.cfg.wans).map((w, i) => {
    const s = st[w.interface] || {};
    return `<div class=card><h3>${esc(w.name || w.id)} — ${esc(w.interface)}</h3>
    <div class=row>
      ${s.up ? pill("link up", "ok") : pill("link down", "err")} ${w.enabled === false ? pill("disabled", "warn") : ""}
      <span class=mono>${esc(s.address || "no address")}</span>
      <span class="muted small">mode ${esc(w.mode)} · metric ${w.metric ?? 0} · gw ${esc(s.gateway || "—")} · dns ${arr(s.dns).map(esc).join(", ") || "—"} · rx ${fmtBytes(s.stats?.rx_bytes)} tx ${fmtBytes(s.stats?.tx_bytes)}</span>
      <span class=spacer></span>
      ${mayWrite() ? `<button class="mini" data-act="wan-edit" data-i="${i}">edit</button>` : ""}
    </div>
    <div class="wanform hidden" data-wf="${i}"></div></div>`;
  }).join("") + `<p class="muted small">WAN definitions live in the configuration; editing here rewrites <span class=mono>config.wans</span> through the normal commit path.</p>`;
}

function wanForm(w) {
  return `<form class="grid wanform-grid">
    <div><label>enabled</label><input type=checkbox name=on ${w.enabled !== false ? "checked" : ""}></div>
    <div><label>metric</label><input name=metric type=number value="${w.metric ?? 0}"></div>
    <div class=span2><label>DNS (comma separated)</label><input name=dns value="${(w.dns || []).join(", ")}"></div>
    <div class=span2><label>static config JSON — {"address":"1.2.3.4/24","gateway":"1.2.3.1","dns":["9.9.9.9"]} (switches mode to static)</label><input name=static value="${esc(w.static ? JSON.stringify(w.static) : "")}"></div>
    <button type=submit>Save WAN</button></form>`;
}

async function viewNetworks(v) {
  const nets = S.cfg.networks || [];
  v.innerHTML = `<h1>Networks</h1>
  <table><tr><th>Name</th><th>Interface</th><th>Subnet</th><th>VLAN</th><th>Members</th><th>DHCP</th><th>Zone</th><th>Internet</th><th>LAN access</th><th></th></tr>
  ${nets.map((n, i) => `<tr><td><b>${esc(n.name)}</b></td><td class=mono>${esc(n.interface)}</td>
    <td class=mono>${esc(n.subnet)}</td><td>${n.vlan ? esc(n.vlan.parent) + "." + n.vlan.id : ""}</td>
    <td class="mono small">${arr(n.members).map(esc).join(", ")}</td>
    <td>${n.dhcp?.enabled ? pill("pool " + (n.dhcp.start || "") + "–" + (n.dhcp.end || ""), "ok") : pill("off")}</td>
    <td>${pill(esc(n.zone))}</td><td>${yn(n.internet_access !== false)}</td><td>${yn(n.access_to_lan)}</td>
    <td class=row>${mayWrite() ? `<button class="mini" data-act="net-edit" data-i="${i}">edit</button>
      <button class="mini danger" data-act="net-del" data-id="${esc(n.id)}">✕</button>` : ""}</td></tr>`).join("")}
  </table>
  <div id=nform></div>`;
  if (mayWrite()) $("#nform").innerHTML = netForm({});
}

function netForm(n) {
  const vlan = n.vlan || {};
  return `<h2>${n.id ? "Edit network — " + esc(n.name) : "Add network"}</h2>
  <form data-form=net class=grid>
    <div><label>name</label><input name=name required value="${esc(n.name || "")}" placeholder=guest></div>
    <div><label>subnet (router addr CIDR)</label><input name=subnet required value="${esc(n.subnet || "")}" placeholder="10.10.0.1/24"></div>
    <div><label>interface</label><input name=interface value="${esc(n.interface || "")}" placeholder="br-&lt;name&gt;"></div>
    <div><label>zone</label><input name=zone value="${esc(n.zone || "")}" placeholder=LAN></div>
    <div><label>vlan id (opt)</label><input name=vlan type=number value="${vlan.id || ""}"></div>
    <div><label>vlan parent</label><input name=parent value="${esc(vlan.parent || "")}" placeholder=eth1></div>
    <div class=span2><label>bridge members (comma separated)</label><input name=members value="${(n.members || []).join(", ")}" placeholder="lan1, lan2"></div>
    <div><label>DHCP</label><select name=dhcp><option value=1 ${n.dhcp?.enabled ? "selected" : ""}>on</option><option value=0 ${!n.dhcp?.enabled ? "selected" : ""}>off</option></select></div>
    <div><label>pool start</label><input name=start value="${esc(n.dhcp?.start || "")}"></div>
    <div><label>pool end</label><input name=end value="${esc(n.dhcp?.end || "")}"></div>
    <div><label>lease (s)</label><input name=lease type=number value="${n.dhcp?.lease_seconds || 7200}"></div>
    <div><label>internet access</label><select name=internet><option value=1 ${n.internet_access !== false ? "selected" : ""}>allow</option><option value=0 ${n.internet_access === false ? "selected" : ""}>deny</option></select></div>
    <div><label>access to LAN</label><select name=lan>${n.access_to_lan ? `<option value=1 selected>allow</option><option value=0>deny</option>` : `<option value=1>allow</option><option value=0 selected>deny</option>`}</select></div>
    <div><label>commit window</label><span class="muted small">${esc(windowLabel())}</span></div>
    <button type=submit>${n.id ? "Save network" : "Add network"}</button>
  </form>`;
}

function netFromForm(f) {
  const val = n => F(f, n).value.trim();
  const n = {
    name: val("name"), subnet: val("subnet"), zone: (val("zone") || val("name")).toUpperCase(),
    interface: val("interface"),
    dhcp: { enabled: F(f, "dhcp").value === "1", start: val("start"), end: val("end"), lease_seconds: +F(f, "lease").value || undefined },
    internet_access: F(f, "internet").value === "1", access_to_lan: F(f, "lan").value === "1",
  };
  if (!n.interface) n.interface = "br-" + n.name;
  if (F(f, "vlan").value) {
    const id = +F(f, "vlan").value, parent = val("parent") || "eth1";
    n.vlan = { parent, id };
    if (!val("interface")) n.interface = parent + "." + id;
  }
  if (val("members")) n.members = val("members").split(",").map(s => s.trim()).filter(Boolean);
  const old = (S.cfg.networks || []).find(x => x.name === n.name);
  if (old?.id) n.id = old.id;
  if (old?.ipv6_subnet) n.ipv6_subnet = old.ipv6_subnet;
  return n;
}

async function viewDevices(v) {
  const [devs, leases] = await Promise.all([api("GET", "/devices"), api("GET", "/leases")]);
  v.innerHTML = `<h1>Devices</h1>
  <table><tr><th>Name</th><th>IPv4</th><th>MAC</th><th>Hostname</th><th>Network</th><th>Source</th><th>Seen</th><th></th></tr>
  ${arr(devs).map(d => `<tr><td><b>${esc(d.friendly_name || d.hostname || "")}</b></td>
    <td class=mono>${esc(d.ipv4 || "")}</td><td class="mono small">${esc(d.mac)}</td><td>${esc(d.hostname || "")}</td>
    <td>${esc(d.network || "")}</td><td>${pill(esc(d.source))}</td><td class="muted small">${ago(d.last_seen)}</td>
    <td>${mayWrite() ? `<button class="mini" data-act="dev-rename" data-mac="${esc(d.mac)}" data-cur="${esc(d.friendly_name || "")}">rename</button>` : ""}</td></tr>`).join("") || "<tr><td colspan=8 class=muted>no devices observed yet</td></tr>"}
  </table>
  <h2>DHCP leases</h2>
  <table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Expires</th></tr>
  ${arr(leases).map(l => `<tr><td class=mono>${esc(l.ip)}</td><td class="mono small">${esc(l.mac)}</td><td>${esc(l.hostname || "")}</td><td class="muted small">${new Date(l.expiry).toLocaleString()}</td></tr>`).join("") || "<tr><td colspan=4 class=muted>no active leases</td></tr>"}</table>`;
}

async function viewFirewall(v) {
  const rules = S.cfg.firewall_rules || [];
  v.innerHTML = `<h1>Firewall</h1>
  <table><tr><th></th><th>Name</th><th>Src → Dst</th><th>Proto</th><th>Ports</th><th>Action</th><th></th></tr>
  ${rules.map((r, i) => `<tr><td>${r.enabled ? pill("on", "ok") : pill("off")}</td><td><b>${esc(r.name || r.id)}</b></td>
    <td class=mono>${esc(r.source_zone)} → ${esc(r.dest_zone)}</td><td>${esc(r.protocol)}</td>
    <td class=mono>${arr(r.ports).map(p => p.start === p.end ? p.start : p.start + "-" + p.end).join(", ")}</td>
    <td>${pill(esc(r.action), r.action === "accept" ? "ok" : r.action === "drop" ? "err" : "warn")}</td>
    <td class=row>${mayWrite() ? `<button class="mini" data-act="fw-toggle" data-i="${i}">${r.enabled ? "disable" : "enable"}</button>
      <button class="mini danger" data-act="fw-del" data-id="${esc(r.id)}">✕</button>` : ""}</td></tr>`).join("") || "<tr><td colspan=7 class=muted>no rules — zone defaults only</td></tr>"}
  </table>
  ${mayWrite() ? `<h2>Add rule</h2>
  <form data-form=fw class=grid>
    <div><label>name</label><input name=name placeholder="block-telnet"></div>
    <div><label>source zone</label><input name=src required value=GUEST></div>
    <div><label>dest zone</label><input name=dst required value=LAN></div>
    <div><label>protocol</label><select name=proto><option>tcp</option><option>udp</option><option>any</option><option>icmp</option></select></div>
    <div><label>ports (e.g. 23 or 8000-8100)</label><input name=ports placeholder=any></div>
    <div><label>action</label><select name=action><option>drop</option><option>reject</option><option>accept</option></select></div>
    <button type=submit>Add rule</button></form>` : ""}`;
}

function parsePorts(s) {
  s = (s || "").trim(); if (!s) return [];
  return s.split(",").map(p => { const [a, b] = p.split("-"); return { start: +a, end: +(b || a) }; });
}

async function viewPF(v) {
  const pfs = S.cfg.port_forwards || [];
  v.innerHTML = `<h1>Port Forwards</h1>
  <table><tr><th></th><th>Name</th><th>WAN</th><th>Proto</th><th>External</th><th>Internal</th><th></th></tr>
  ${arr(pfs).map((p, i) => `<tr><td>${p.enabled ? pill("on", "ok") : pill("off")}</td><td><b>${esc(p.name || p.id)}</b></td>
    <td class=mono>${esc(p.wan)}</td><td>${esc(p.protocol)}</td><td class=mono>${p.external_port}</td>
    <td class=mono>${esc(p.internal_ip)}:${p.internal_port}</td>
    <td class=row>${mayWrite() ? `<button class="mini" data-act="pf-toggle" data-i="${i}">${p.enabled ? "disable" : "enable"}</button>
      <button class="mini danger" data-act="pf-del" data-id="${esc(p.id)}">✕</button>` : ""}</td></tr>`).join("") || "<tr><td colspan=7 class=muted>no port forwards</td></tr>"}
  </table>
  ${mayWrite() ? `<h2>Add forward</h2>
  <form data-form=pf class=grid>
    <div><label>name</label><input name=name placeholder=nas-ssh></div>
    <div><label>WAN interface</label><select name=wan>${arr(S.cfg.wans).map(w => `<option>${esc(w.interface)}</option>`).join("")}</select></div>
    <div><label>protocol</label><select name=proto><option>tcp</option><option>udp</option></select></div>
    <div><label>external port</label><input name=ext type=number required min=1 max=65535></div>
    <div><label>internal IP</label><input name=ip required placeholder="192.168.1.50"></div>
    <div><label>internal port</label><input name=int type=number required min=1 max=65535></div>
    <button type=submit>Add forward</button></form>` : ""}`;
}

async function viewVPN(v) {
  const tuns = await api("GET", "/wireguard/tunnels");
  v.innerHTML = `<h1>VPN — WireGuard</h1>
  ${arr(tuns).map(t => `<div class=card><h3>${esc(t.name)} ${pill(esc(t.zone || "VPN"))}</h3>
    <div class=kv><b>address</b><span class=mono>${esc(t.address)}</span>
    <b>listen</b><span>${t.listen_port || 51820}/udp</span>
    <b>peers</b><span>${(t.peers || []).length}${(t.peers || []).length ? ": " + t.peers.map(p => esc(p.name || String(p.public_key || "").slice(0, 10) + "…")).join(", ") : ""}</span></div>
    ${mayWrite() ? `<div class=row style="margin-top:8px"><button class="mini danger" data-act=wg-del data-name="${esc(t.name)}">delete tunnel</button></div>` : ""}
  </div>`).join("") || "<p class=muted>No WireGuard tunnels.</p>"}
  ${mayWrite() ? `<h2>Add tunnel</h2>
  <form data-form=wg class=grid>
    <div><label>name</label><input name=name required value=wg0></div>
    <div><label>tunnel network CIDR</label><input name=address required placeholder="10.8.0.1/24"></div>
    <div><label>listen port</label><input name=port type=number placeholder=51820></div>
    <div><label>zone</label><input name=zone value=VPN></div>
    <div><label>private key</label><input name=key type=password required autocomplete=new-password></div>
    <div class=span2><label>peers JSON array [{name,public_key,allowed_ips}]</label><input name=peers placeholder='[{"name":"phone","public_key":"…","allowed_ips":["10.8.0.2/32"]}]'></div>
    <button type=submit>Add tunnel</button></form>
  <p class="muted small">Generate keys with <span class=mono>wg genkey</span> / <span class=mono>wg pubkey</span> on any WireGuard host.</p>` : ""}`;
}

async function viewTraffic(v) {
  const tp = S.cfg.traffic_policies || [];
  v.innerHTML = `<h1>Traffic Management</h1>
  <table><tr><th>Name</th><th>Interface</th><th>Up</th><th>Down</th><th>SQM</th><th>Qdisc</th><th></th></tr>
  ${tp.map((t, i) => `<tr><td><b>${esc(t.name)}</b></td><td class=mono>${esc(t.interface)}</td><td>${t.up_mbps} Mbps</td>
    <td>${t.down_mbps} Mbps</td><td>${yn(t.sqm)}</td><td>${esc(t.qdisc || "cake")}</td>
    <td>${mayWrite() ? `<button class="mini danger" data-act=tp-del data-i="${i}">✕</button>` : ""}</td></tr>`).join("") || "<tr><td colspan=7 class=muted>no shaping policies — traffic control is inactive</td></tr>"}
  </table>
  ${mayWrite() ? `<h2>Add policy</h2>
  <form data-form=tp class=grid>
    <div><label>name</label><input name=name required></div>
    <div><label>interface</label><input name=iface required placeholder=eth0></div>
    <div><label>up Mbps</label><input name=up type=number required min=1></div>
    <div><label>down Mbps</label><input name=down type=number required min=1></div>
    <div><label>qdisc</label><select name=qdisc><option>cake</option><option>fq_codel</option><option>tbf</option></select></div>
    <div><label>SQM</label><select name=sqm><option value=1>yes</option><option value=0>no</option></select></div>
    <button type=submit>Add policy</button></form>
  <p class="muted small">Policies shape traffic with tc on the named interface; changes go through the config store (subject to the commit window in the sidebar).</p>` : ""}`;
}

async function viewSystem(v) {
  const [svcs, dhcp, revs, toks, cfg] = await Promise.all([
    api("GET", "/services"), api("GET", "/config/dhcp"), api("GET", "/config/revisions"),
    mayWrite() ? api("GET", "/auth/tokens") : Promise.resolve([]), api("GET", "/config")]);
  v.innerHTML = `<h1>System</h1>
  <div class=cards>
    ${card("Services", arr(svcs).map(s => `<div class=row>${pill(s.status, pcls(s.status))} <b>${esc(s.name)}</b> <span class="muted small">${esc(s.detail || "")}</span></div>`).join("") || "<span class=muted>none</span>")}
    ${card("DHCP server", kv(Object.entries(dhcp).map(([k, val]) => [k, esc(typeof val === "object" ? JSON.stringify(val) : String(val))])))}
    ${mayWrite() ? card("Change password", `<form data-form=pwd style=display:grid;gap:6px>
      <input name=old type=password placeholder="current password" autocomplete=current-password>
      <input name=new type=password placeholder="new password" autocomplete=new-password required>
      <button type=submit class=mini>Change password</button></form>`) : ""}
  </div>
  <h2>Configuration</h2>
  <textarea id=cfgEditor spellcheck=false>${esc(JSON.stringify(cfg, null, 2))}</textarea>
  <div class=row style="margin-top:8px">
    ${mayWrite() ? `<button data-act=cfg-validate>Validate</button>
    <button data-act=cfg-save>Save &amp; apply</button>
    <span class=spacer></span><span class="muted small">commit window: ${esc(windowLabel())}</span>`
    : `<span class="muted small">read-only view</span>`}
  </div>
  ${mayWrite() ? `<h2>Transaction (draft → validate → apply → commit)</h2>
  <div class=row>
    <input id=txnId class=mono placeholder="no active transaction" readonly style=width:320px>
    <button data-act=txn-begin>Begin</button>
    <button data-act=txn-put>Push editor draft</button>
    <button data-act=txn-validate>Validate</button>
    <button data-act=txn-apply>Apply (window)</button>
    <button data-act=txn-commit>Commit</button>
    <button data-act=txn-rollback class=danger>Rollback</button>
  </div>` : ""}
  <h2>Revisions</h2>
  <table><tr><th>Rev</th><th>Time</th><th>Author</th><th>Message</th><th></th></tr>
  ${arr(revs).map(r => `<tr><td>${r.rev}</td><td class="muted small">${new Date(r.time).toLocaleString()}</td><td>${esc(r.author)}</td><td>${esc(r.message)}</td>
    <td>${mayWrite() ? `<button class="mini" data-act=rev-restore data-rev="${r.rev}">restore</button>` : ""}</td></tr>`).join("")}</table>
  ${mayWrite() ? `<h2>API tokens</h2>
  <table><tr><th>Name</th><th>Role</th><th>Created</th><th></th></tr>
  ${arr(toks).map(tk => `<tr><td>${esc(tk.name)}</td><td>${pill(esc(tk.role))}</td><td class="muted small">${new Date(tk.created).toLocaleDateString()}</td>
    <td><button class="mini danger" data-act=tok-del data-id="${esc(tk.id)}">✕</button></td></tr>`).join("")}</table>
  <form data-form=token class=grid>
    <div><label>token name</label><input name=tokname required placeholder=home-automation></div>
    <div><label>role</label><select name=role><option>admin</option><option>readonly</option></select></div>
    <button type=submit>Create token</button></form>
  <p class="muted small">The full token value is shown <b>once</b> at creation.</p>` : ""}`;
}

async function viewLogs(v) {
  const [audit, evs] = await Promise.all([api("GET", "/audit?limit=200"), api("GET", "/events?limit=200")]);
  v.innerHTML = `<h1>Logs</h1>
  <h2>Audit (${(audit || []).length})</h2>
  <table><tr><th>Time</th><th>User</th><th>Action</th><th>Object</th><th>Result</th></tr>
  ${arr(audit).map(a => `<tr><td class="muted small">${new Date(a.time).toLocaleString()}</td><td>${esc(a.user)}</td>
    <td class=mono>${esc(a.action)}</td><td class=small>${esc(a.object || "")}</td>
    <td>${pill(esc(a.result), pcls(a.result))}</td></tr>`).join("")}</table>
  <h2>Events (${(evs || []).length})</h2>
  <table>${arr(evs).slice().reverse().reverse().map(e => `<tr><td class="muted small" style=width:150px>${new Date(e.time).toLocaleString()}</td><td class=mono>${esc(e.kind)}</td><td class=muted>${esc(e.detail || "")}</td></tr>`).join("")}</table>`;
}

/* ---------- actions ---------- */
const ACTIONS = {
  commit: guard(async () => { await api("POST", "/config/commit", { commit_token: S.pending.commit_token }); toast("Change confirmed.", "ok"); await pollPending(); render(); }),
  revert: guard(async () => { await api("POST", "/config/rollback"); toast("Reverted.", "warn"); await pollPending(); render(); }),
  "net-edit": el => { $("#nform").innerHTML = netForm(S.cfg.networks[+el.dataset.i]); window.scrollTo(0, document.body.scrollHeight); },
  "net-del": guard(async el => { if (!confirm("Delete network and tear down its bridge/DHCP?")) return; applied(await api("DELETE", "/networks/" + el.dataset.id + confQS())); }),
  "fw-toggle": guard(async el => { const r = { ...S.cfg.firewall_rules[+el.dataset.i] }; r.enabled = !r.enabled; applied(await api("PATCH", "/firewall/rules/" + r.id + confQS(), r)); }),
  "fw-del": guard(async el => { applied(await api("DELETE", "/firewall/rules/" + el.dataset.id + confQS())); }),
  "pf-toggle": guard(async el => { const r = { ...S.cfg.port_forwards[+el.dataset.i] }; r.enabled = !r.enabled; applied(await api("PATCH", "/portforwards/" + r.id + confQS(), r)); }),
  "pf-del": guard(async el => { applied(await api("DELETE", "/portforwards/" + r.id + confQS())); }),
  "wg-del": guard(async el => { if (!confirm("Delete WireGuard tunnel " + el.dataset.name + "?")) return; applied(await api("DELETE", "/wireguard/tunnels/" + el.dataset.name + confQS())); }),
  "tp-del": guard(async el => { const c = await api("GET", "/config"); c.traffic_policies.splice(+el.dataset.i, 1); applied(await api("PUT", "/config" + confQS(), c)); }),
  "dev-rename": guard(async el => { const name = prompt("Friendly name:", el.dataset.cur || ""); if (name === null) return; await api("PUT", "/devices/" + el.dataset.mac, { name }); toast("Saved.", "ok"); render(); }),
  "wan-edit": el => {
    const box = document.querySelector(`[data-wf="${el.dataset.i}"]`);
    if (box.classList.contains("hidden")) { box.innerHTML = wanForm(S.cfg.wans[+el.dataset.i]); box.classList.remove("hidden"); }
    else box.classList.add("hidden");
  },
  "cfg-validate": guard(async () => { await api("POST", "/config/validate", JSON.parse($("#cfgEditor").value)); toast("Config valid ✔", "ok"); }),
  "cfg-save": guard(async () => { applied(await api("PUT", "/config" + confQS(), JSON.parse($("#cfgEditor").value))); }),
  "txn-begin": guard(async () => { const t = await api("POST", "/transactions"); S.txn = t.id; $("#txnId").value = t.id; $("#cfgEditor").value = JSON.stringify(t.config, null, 2); toast("Transaction " + esc(t.id) + " begun — edit the config and push.", "ok"); }),
  "txn-put": guard(async () => { await api("PUT", "/transactions/" + reqTxn() + "/config", JSON.parse($("#cfgEditor").value)); toast("Draft stored.", "ok"); }),
  "txn-validate": guard(async () => { await api("POST", "/transactions/" + reqTxn() + "/validate"); toast("Draft valid ✔", "ok"); }),
  "txn-apply": guard(async () => {
    await api("POST", "/transactions/" + reqTxn() + "/apply?confirm_seconds=" + Math.max(60, +$("#confirmSel").value || 120));
    toast("Applied in commit window — use Confirm above or Rollback to undo.", "warn"); pollPending();
  }),
  "txn-commit": guard(async () => { await api("POST", "/transactions/" + reqTxn() + "/commit"); S.txn = ""; toast("Transaction committed.", "ok"); await pollPending(); render(); }),
  "txn-rollback": guard(async () => { await api("POST", "/transactions/" + reqTxn() + "/rollback"); S.txn = ""; toast("Transaction rolled back.", "warn"); await pollPending(); render(); }),
  "rev-restore": guard(async el => { applied(await api("POST", "/config/revisions/" + el.dataset.rev + "/restore" + confQS())); }),
  "tok-del": guard(async el => { applied(await api("DELETE", "/auth/tokens/" + el.dataset.id)); }),
};
const reqTxn = () => { if (!S.txn) throw new Error("no active transaction — press Begin first"); return S.txn; };

/* ---------- form submits ---------- */
const FORMS = {
  net: async f => {
    const n = netFromForm(f);
    applied(n.id ? await api("PUT", "/networks/" + n.id + confQS(), n) : await api("POST", "/networks" + confQS(), n));
  },
  fw: async f => {
    const r = { id: "ui" + (Date.now() % 1000000), name: F(f, "name").value.trim(), source_zone: F(f, "src").value.trim().toUpperCase(), dest_zone: F(f, "dst").value.trim().toUpperCase(), protocol: F(f, "proto").value, ports: parsePorts(F(f, "ports").value), action: F(f, "action").value, enabled: true };
    applied(await api("POST", "/firewall/rules" + confQS(), r));
  },
  pf: async f => {
    const p = { id: "ui" + (Date.now() % 1000000), name: F(f, "name").value.trim(), wan: F(f, "wan").value, protocol: F(f, "proto").value, external_port: +F(f, "ext").value, internal_ip: F(f, "ip").value.trim(), internal_port: +F(f, "int").value, enabled: true };
    applied(await api("POST", "/portforwards" + confQS(), p));
  },
  wg: async f => {
    const t = { name: F(f, "name").value.trim(), address: F(f, "address").value.trim(), listen_port: +F(f, "port").value || 51820, zone: F(f, "zone").value.trim() || "VPN", private_key: F(f, "key").value };
    if (F(f, "peers").value.trim()) t.peers = JSON.parse(F(f, "peers").value);
    applied(await api("POST", "/wireguard/tunnels" + confQS(), t));
  },
  tp: async f => {
    const c = await api("GET", "/config");
    (c.traffic_policies = c.traffic_policies || []).push({ name: F(f, "name").value.trim(), interface: F(f, "iface").value.trim(), up_mbps: +F(f, "up").value, down_mbps: +F(f, "down").value, sqm: F(f, "sqm").value === "1", qdisc: F(f, "qdisc").value });
    applied(await api("PUT", "/config" + confQS(), c));
  },
  pwd: async f => { await api("POST", "/auth/password", { old_password: f.elements.old.value, new_password: f.elements.new.value }); toast("Password changed.", "ok"); f.reset(); },
  token: async f => {
    const t = await api("POST", "/auth/tokens", { name: f.elements.tokname.value.trim(), role: f.elements.role.value });
    toast(`Token <b class=mono>${esc(t.token)}</b> — copy it now; shown only once.`, "ok");
    render();
  },
};

/* WAN edit form (rendered inside .wanform boxes) */
async function saveWANForm(box) {
  const i = +box.dataset.wf, c = await api("GET", "/config"), w = c.wans[i];
  const f = box.querySelector("form");
  w.enabled = f.elements.on.checked;
  w.metric = +f.elements.metric.value;
  w.dns = f.elements.dns.value.split(",").map(s => s.trim()).filter(Boolean);
  const st = f.elements.static.value.trim();
  if (st) { w.mode = "static"; w.static = JSON.parse(st); }
  else if (w.mode === "static") return toast("static WAN needs a static block", "err");
  applied(await api("PUT", "/config" + confQS(), c));
}

/* ---------- app shell ---------- */
async function render() {
  const route = (location.hash.replace("#/", "") || "dashboard");
  const [title, fn] = VIEWS[route] || VIEWS.dashboard;
  S.view = route;
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("active", a.dataset.r === route));
  const v = $("#view");
  v.innerHTML = `<p class=muted>Loading ${esc(title)}…</p>`;
  try { await fn(v); } catch (e) { v.innerHTML = `<p class=err>${esc(e.message)}</p>`; }
}

function startTimers() {
  stopTimers();
  pollTop(); pollPending();
  S.timers.push(setInterval(pollTop, 5000), setInterval(pollPending, 4000));
  S.timers.push(setInterval(() => { if (["dashboard", "logs"].includes(S.view)) render(); }, 15000));
}
const stopTimers = () => { S.timers.forEach(clearInterval); S.timers = []; };

async function boot() {
  if (!S.token) return showLogin();
  try {
    const me = await api("GET", "/auth/whoami");
    S.user = me.user; S.role = me.role;
  } catch { return showLogin(); }
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  $("#whoami").textContent = S.user + " · " + S.role;
  $("#nav").innerHTML = Object.entries(VIEWS).map(([k, [t]]) => `<a href="#/${k}" data-r="${k}">${t}</a>`).join("");
  await loadCfg().catch(e => toast(esc(e.message), "err"));
  startTimers();
  render();
}

function showLogin() {
  stopTimers();
  $("#app").classList.add("hidden"); $("#login").classList.remove("hidden");
}
async function doLogin(e) {
  e.preventDefault();
  $("#loginErr").textContent = "";
  try {
    const r = await api("POST", "/auth/login", { username: $("#luser").value, password: $("#lpass").value });
    S.token = r.token;
    localStorage.setItem("router_token", r.token);
    boot();
  } catch (err) { $("#loginErr").textContent = err.message; }
}
async function logout(callApi = true) {
  if (callApi) { try { await api("POST", "/auth/logout"); } catch { /* ignore */ } }
  S.token = "";
  localStorage.removeItem("router_token");
  showLogin();
}

/* delegated events */
document.addEventListener("click", e => {
  const el = e.target.closest("[data-act]");
  if (el && ACTIONS[el.dataset.act]) ACTIONS[el.dataset.act](el);
});
document.addEventListener("submit", e => {
  const f = e.target;
  if (f.dataset.form && FORMS[f.dataset.form]) {
    e.preventDefault();
    FORMS[f.dataset.form](f).catch(err => toast(esc(err.message), "err"));
  } else if (f.classList.contains("wanform-grid")) {
    e.preventDefault();
    saveWANForm(f.closest(".wanform")).catch(err => toast(esc(err.message), "err"));
  }
});
window.addEventListener("hashchange", () => { if (S.token) render(); });
$("#loginForm").addEventListener("submit", doLogin);
$("#logoutBtn").addEventListener("click", () => logout());
boot();
