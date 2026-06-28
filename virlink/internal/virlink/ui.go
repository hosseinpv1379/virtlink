// ui.go — single-file HTML dashboard served at GET /
// Embedded directly in the binary; no external files needed.
package virlink

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>virlink — tunnel monitor</title>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;
  --border:#30363d;--text:#c9d1d9;--muted:#6e7681;
  --green:#3fb950;--yellow:#d29922;--red:#f85149;
  --blue:#58a6ff;--purple:#bc8cff;--cyan:#39c5cf;
  --font:'SF Mono',ui-monospace,'Cascadia Code',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);
     min-height:100vh;padding:28px 20px}
a{color:var(--blue);text-decoration:none}

/* ── top bar ── */
.topbar{max-width:1000px;margin:0 auto 28px;display:flex;
        justify-content:space-between;align-items:flex-end}
.logo{font-size:1.3rem;color:var(--blue);font-weight:700;letter-spacing:.05em}
.logo span{color:var(--muted);font-size:.75rem;font-weight:400;margin-left:10px}
.refresh-status{font-size:.7rem;color:var(--muted);display:flex;align-items:center;gap:6px}

/* ── grid ── */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));
      gap:16px;max-width:1000px;margin:0 auto}
.card{background:var(--surface);border:1px solid var(--border);
      border-radius:10px;padding:22px}
.card-title{font-size:.62rem;text-transform:uppercase;letter-spacing:.18em;
            color:var(--muted);margin-bottom:18px;display:flex;
            align-items:center;gap:8px}
.card-title .badge{background:var(--surface2);border-radius:4px;
                   padding:1px 6px;font-size:.6rem;color:var(--cyan)}

/* ── status dot ── */
.status-row{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;position:relative}
.dot::after{content:'';position:absolute;inset:-4px;border-radius:50%;opacity:.3}
.dot.connected{background:var(--green)}
.dot.connected::after{background:var(--green);animation:ring 2s ease-out infinite}
.dot.degraded{background:var(--yellow)}
.dot.degraded::after{background:var(--yellow);animation:ring 1s ease-out infinite}
.dot.dead{background:var(--red)}
.dot.waiting{background:var(--muted)}
@keyframes ring{0%{opacity:.4;transform:scale(1)}100%{opacity:0;transform:scale(2.5)}}
.status-label{font-size:1.1rem;font-weight:700;letter-spacing:.08em}
.connected .status-label,.status-label.connected{color:var(--green)}
.degraded  .status-label,.status-label.degraded {color:var(--yellow)}
.dead      .status-label,.status-label.dead     {color:var(--red)}
.waiting   .status-label,.status-label.waiting  {color:var(--muted)}

/* ── info rows ── */
.info{display:flex;flex-direction:column;gap:8px}
.info-row{display:flex;justify-content:space-between;align-items:center;
          font-size:.78rem;padding:5px 0;border-bottom:1px solid #21262d}
.info-row:last-child{border:none}
.ik{color:var(--muted)}
.iv{color:var(--text);font-weight:500;text-align:right}

/* ── probe stats ── */
.probe-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;
            margin-top:4px}
.probe-item{text-align:center;padding:14px 8px;background:var(--surface2);
            border-radius:8px}
.probe-num{font-size:1.6rem;font-weight:700;color:var(--blue);
           line-height:1.1}
.probe-lbl{font-size:.62rem;color:var(--muted);text-transform:uppercase;
           letter-spacing:.1em;margin-top:4px}

/* ── bandwidth ── */
.bw-full{grid-column:1/-1}
.bw-row{margin-bottom:18px}
.bw-header{display:flex;justify-content:space-between;align-items:baseline;
           font-size:.78rem;margin-bottom:8px}
.bw-dir{color:var(--muted);display:flex;align-items:center;gap:6px}
.bw-arrow{font-size:1rem}
.bw-val{font-size:1rem;font-weight:700;color:var(--text)}
.bw-mbs{font-size:.72rem;color:var(--muted);margin-left:6px}
.bar-track{background:#0d1117;border:1px solid var(--border);border-radius:6px;
           height:12px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px;transition:width .7s cubic-bezier(.4,0,.2,1);
          width:0%}
.bar-fill.ul{background:linear-gradient(90deg,#1158c7,var(--blue),var(--cyan))}
.bar-fill.dl{background:linear-gradient(90deg,#6e40c9,var(--purple),#f778ba)}

.bench-meta{display:flex;gap:24px;margin-top:16px;flex-wrap:wrap}
.bench-meta-item{font-size:.72rem}
.bench-meta-key{color:var(--muted)}
.bench-meta-val{color:var(--text)}

/* ── button ── */
.btn{width:100%;margin-top:18px;padding:11px;
     background:var(--surface2);border:1px solid var(--border);
     border-radius:7px;color:var(--blue);font-family:var(--font);
     font-size:.8rem;cursor:pointer;letter-spacing:.06em;
     transition:background .15s,border-color .15s;display:flex;
     align-items:center;justify-content:center;gap:8px}
.btn:hover:not(:disabled){background:#2d333b;border-color:var(--blue)}
.btn:disabled{color:var(--muted);cursor:not-allowed}
.btn.running{animation:btn-pulse 1.2s ease-in-out infinite}
@keyframes btn-pulse{0%,100%{opacity:1}50%{opacity:.55}}
.bench-note{font-size:.68rem;color:var(--muted);text-align:center;margin-top:10px}
.err{color:var(--red);font-size:.75rem;margin-top:10px;min-height:1.2em}

/* ── interface picker ── */
.iface-bar{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.iface-bar label{font-size:.72rem;color:var(--muted)}
.iface-select{background:var(--surface2);border:1px solid var(--border);border-radius:6px;
             color:var(--text);font-family:var(--font);font-size:.78rem;padding:7px 10px;
             min-width:180px}
.iface-table{width:100%;border-collapse:collapse;font-size:.72rem;margin-top:8px}
.iface-table th,.iface-table td{padding:6px 8px;text-align:left;border-bottom:1px solid var(--surface2)}
.iface-table th{color:var(--muted);font-weight:500;text-transform:uppercase;font-size:.6rem;letter-spacing:.08em}
.iface-table td.num{text-align:right;font-variant-numeric:tabular-nums}
.iface-up{color:var(--green)}.iface-down{color:var(--red)}
.iface-kind{font-size:.62rem;color:var(--cyan)}

/* ── spinner ── */
.spin{width:10px;height:10px;border:1.5px solid var(--muted);
      border-top-color:var(--blue);border-radius:50%;
      animation:spin .7s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── footer ── */
.footer{max-width:1000px;margin:28px auto 0;font-size:.68rem;color:var(--muted);
        display:flex;gap:20px;flex-wrap:wrap}
</style>
</head>
<body>

<div class="topbar">
  <div>
    <div class="logo">⬡ virlink <span>tunnel health monitor</span></div>
  </div>
  <div class="refresh-status" id="rs">
    <span class="spin"></span> loading...
  </div>
</div>

<div class="grid">

  <!-- STATUS -->
  <div class="card" id="status-card">
    <div class="card-title">Tunnel Status</div>
    <div class="status-row">
      <div class="dot waiting" id="dot"></div>
      <div class="status-label waiting" id="hs-label">WAITING</div>
    </div>
    <div class="info">
      <div class="info-row"><span class="ik">interface</span><span class="iv" id="iface">—</span></div>
      <div class="info-row"><span class="ik">overlay IP</span><span class="iv" id="overlay">—</span></div>
      <div class="info-row"><span class="ik">peer IP</span><span class="iv" id="peer">—</span></div>
      <div class="info-row"><span class="ik">uptime</span><span class="iv" id="uptime">—</span></div>
      <div class="info-row"><span class="ik">last probe</span><span class="iv" id="last-seen">—</span></div>
    </div>
  </div>

  <!-- INTERFACES -->
  <div class="card" id="iface-card">
    <div class="card-title">Tunnel Interfaces <span class="badge">panel :6543</span></div>
    <div class="iface-bar">
      <label for="iface-select">test via</label>
      <select class="iface-select" id="iface-select" onchange="onIfaceChange()">
        <option value="">all (ECMP)</option>
      </select>
    </div>
    <table class="iface-table" id="iface-table" style="display:none">
      <thead><tr>
        <th>interface</th><th>state</th><th>rx</th><th>tx</th>
      </tr></thead>
      <tbody id="iface-tbody"></tbody>
    </table>
  </div>

  <!-- PROBES -->
  <div class="card">
    <div class="card-title">Handshake Probes <span class="badge">UDP</span></div>
    <div class="probe-grid">
      <div class="probe-item">
        <div class="probe-num" id="tx-probes">—</div>
        <div class="probe-lbl">sent</div>
      </div>
      <div class="probe-item">
        <div class="probe-num" id="rx-probes">—</div>
        <div class="probe-lbl">received</div>
      </div>
      <div class="probe-item">
        <div class="probe-num" id="loss-val">—</div>
        <div class="probe-lbl">loss</div>
      </div>
    </div>
    <div id="probe-err" class="err"></div>
  </div>

  <!-- BANDWIDTH -->
  <div class="card bw-full">
    <div class="card-title">
      Bandwidth Test
      <span class="badge">4 streams × 5 s</span>
    </div>

    <!-- DOWNLOAD first (speedtest standard) -->
    <div class="bw-row">
      <div class="bw-header">
        <span class="bw-dir"><span class="bw-arrow" style="color:var(--purple)">▼</span> Download  <span style="color:var(--muted);font-size:.65rem">peer → you</span></span>
        <span><span class="bw-val" id="dl-mbps">—</span><span class="bw-mbs" id="dl-mbs"></span></span>
      </div>
      <div class="bar-track"><div class="bar-fill dl" id="dl-bar"></div></div>
    </div>

    <!-- UPLOAD second -->
    <div class="bw-row">
      <div class="bw-header">
        <span class="bw-dir"><span class="bw-arrow" style="color:var(--blue)">▲</span> Upload  <span style="color:var(--muted);font-size:.65rem">you → peer</span></span>
        <span><span class="bw-val" id="ul-mbps">—</span><span class="bw-mbs" id="ul-mbs"></span></span>
      </div>
      <div class="bar-track"><div class="bar-fill ul" id="ul-bar"></div></div>
    </div>

    <div id="bench-meta" class="bench-meta" style="display:none">
      <div class="bench-meta-item">
        <span class="bench-meta-key">streams </span>
        <span class="bench-meta-val" id="b-streams">—</span>
      </div>
      <div class="bench-meta-item">
        <span class="bench-meta-key">duration </span>
        <span class="bench-meta-val" id="b-dur">—</span>
      </div>
      <div class="bench-meta-item">
        <span class="bench-meta-key">tested at </span>
        <span class="bench-meta-val" id="b-at">—</span>
      </div>
    </div>

    <button class="btn" id="bench-btn" onclick="runBench()">
      <span id="btn-icon">▶</span> Run Bandwidth Test
    </button>
    <div id="bench-err" class="err"></div>
    <div class="bench-note">
      Traffic flows through the tunnel overlay — measures real link throughput.
      Pick an interface above to bench a single worker. Results cached 2 min.
    </div>
  </div>

</div>

<div class="footer">
  <span>⬡ virlink v` + version + `</span>
  <span>health <a href="/health">/health</a> · bench <a href="/bench">/bench</a></span>
</div>

<script>
let maxMbps = 1000;
let selectedIface = '';

function benchQuery() {
  const sel = document.getElementById('iface-select');
  const v = sel ? sel.value : '';
  if (!v) return '';
  return '?iface=' + encodeURIComponent(v);
}

function healthQuery() {
  const q = benchQuery();
  return q ? '/health' + q : '/health';
}

function onIfaceChange() {
  const sel = document.getElementById('iface-select');
  selectedIface = sel ? sel.value : '';
  fetchHealth();
}

function populateIfaceSelect(ifaces) {
  const sel = document.getElementById('iface-select');
  if (!sel || !ifaces || !ifaces.length) return;
  const workers = ifaces.filter(i => i.kind === 'worker' || i.kind === 'tunnel');
  if (workers.length <= 1) {
    sel.innerHTML = '<option value="">default</option>';
    workers.forEach(i => {
      const o = document.createElement('option');
      o.value = i.name; o.textContent = i.name;
      sel.appendChild(o);
    });
    return;
  }
  const cur = sel.value;
  sel.innerHTML = '<option value="">all (ECMP)</option><option value="all">each worker</option>';
  workers.forEach(i => {
    const o = document.createElement('option');
    o.value = i.name; o.textContent = i.name;
    sel.appendChild(o);
  });
  if (cur) sel.value = cur;
}

function fmtBytes(n) {
  n = +n || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(2) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}

function renderIfaceTable(ifaces) {
  const tbl = document.getElementById('iface-table');
  const body = document.getElementById('iface-tbody');
  if (!tbl || !body || !ifaces || !ifaces.length) {
    if (tbl) tbl.style.display = 'none';
    return;
  }
  body.innerHTML = '';
  ifaces.forEach(i => {
    const tr = document.createElement('tr');
    const st = i.link_up ? '<span class="iface-up">up</span>' : '<span class="iface-down">down</span>';
    const label = i.label || i.name;
    tr.innerHTML = '<td>' + label + ' <span class="iface-kind">' + (i.kind||'') + '</span></td>'
      + '<td>' + st + '</td>'
      + '<td class="num">' + fmtBytes(i.rx_bytes) + '</td>'
      + '<td class="num">' + fmtBytes(i.tx_bytes) + '</td>';
    body.appendChild(tr);
  });
  tbl.style.display = '';
}

async function fetchHealth() {
  const rs = document.getElementById('rs');
  rs.innerHTML = '<span class="spin"></span> refreshing...';
  try {
    const r = await fetch(healthQuery());
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    applyHealth(d);
    populateIfaceSelect(d.interfaces);
    renderIfaceTable(d.interfaces);
    rs.textContent = '✓ ' + new Date().toLocaleTimeString();
    if (d.last_bench) applyBench(d.last_bench, false);
  } catch(e) {
    rs.textContent = '✗ ' + e.message;
  }
}

function applyHealth(d) {
  const hs = d.handshake || 'waiting';
  const dot = document.getElementById('dot');
  const lbl = document.getElementById('hs-label');
  dot.className = 'dot ' + hs;
  lbl.className = 'status-label ' + hs;
  lbl.textContent = hs.toUpperCase();
  s('iface',     d.interface  || '—');
  s('overlay',   d.overlay_ip || '—');
  s('peer',      d.peer_ip    || '—');
  s('uptime',    d.uptime     || '—');
  s('last-seen', d.last_seen  || '—');
  const tx = d.tx_probes || 0, rx = d.rx_probes || 0;
  s('tx-probes', tx);
  s('rx-probes', rx);
  s('loss-val', tx > 0 ? ((tx - rx) / tx * 100).toFixed(1) + '%' : '—');
}

async function runBench() {
  const btn = document.getElementById('bench-btn');
  const bi  = document.getElementById('btn-icon');
  const err = document.getElementById('bench-err');
  btn.disabled = true;
  btn.classList.add('running');
  bi.textContent = '⏳';
  btn.childNodes[1].textContent = ' Running test (~10 s)...';
  err.textContent = '';
  try {
    const r = await fetch('/bench' + benchQuery());
    const d = await r.json();
    if (d.mode === 'all' && d.workers) {
      const lines = d.workers.map(w =>
        w.interface + ': ↓' + (w.download_mbps||0).toFixed(1) + ' ↑' + (w.upload_mbps||0).toFixed(1) + ' Mbps'
        + (w.error ? ' (' + w.error + ')' : '')
      );
      err.textContent = lines.join('  ·  ');
      if (d.workers.length) applyBench(d.workers[0], true);
    } else if (d.error) {
      err.textContent = '✗ ' + d.error;
    } else {
      applyBench(d, true);
    }
  } catch(e) {
    err.textContent = '✗ ' + e.message;
  } finally {
    btn.disabled = false;
    btn.classList.remove('running');
    bi.textContent = '▶';
    btn.childNodes[1].textContent = ' Run Bandwidth Test';
  }
}

function applyBench(d, animate) {
  // download = peer→you, upload = you→peer  (speedtest convention)
  const dl = +(d.download_mbps || 0);
  const ul = +(d.upload_mbps   || 0);
  const peak = Math.max(dl, ul, 1);
  if (peak > maxMbps * 0.9) maxMbps = peak * 1.3;
  const dlp = Math.min(100, dl / maxMbps * 100).toFixed(1);
  const ulp = Math.min(100, ul / maxMbps * 100).toFixed(1);

  s('dl-mbps', dl.toFixed(1) + ' Mbps');
  s('dl-mbs',  '(' + (+(d.download_mb_s || 0)).toFixed(1) + ' MB/s)');
  s('ul-mbps', ul.toFixed(1) + ' Mbps');
  s('ul-mbs',  '(' + (+(d.upload_mb_s   || 0)).toFixed(1) + ' MB/s)');

  const db = document.getElementById('dl-bar');
  const ub = document.getElementById('ul-bar');
  if (!animate) {
    db.style.transition = 'none'; ub.style.transition = 'none';
  }
  setTimeout(() => { db.style.width = dlp + '%'; ub.style.width = ulp + '%'; }, 20);
  if (!animate) {
    setTimeout(() => { db.style.transition = ''; ub.style.transition = ''; }, 100);
  }

  document.getElementById('bench-meta').style.display = 'flex';
  s('b-streams', (d.streams || '—') + ' parallel');
  s('b-dur',     d.test_duration || '—');
  s('b-at',      d.tested_at || '—');
}

function s(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

fetchHealth();
setInterval(fetchHealth, 5000);
</script>
</body>
</html>`
