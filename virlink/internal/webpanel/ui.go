package webpanel

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>virlink — control panel</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;--text:#c9d1d9;--muted:#6e7681;
--green:#3fb950;--yellow:#d29922;--red:#f85149;--blue:#58a6ff;--purple:#bc8cff;
--font:ui-sans-serif,system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;padding:20px}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:1.35rem;color:var(--blue)}
.sub{color:var(--muted);font-size:.85rem;margin:6px 0 20px}
.grid{display:grid;grid-template-columns:1fr 1.2fr;gap:16px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px}
.card-title{font-size:.65rem;text-transform:uppercase;letter-spacing:.15em;color:var(--muted);margin-bottom:14px}
.tunnel-list{display:flex;flex-direction:column;gap:8px;max-height:420px;overflow:auto}
.t-item{padding:12px 14px;border:1px solid var(--border);border-radius:8px;cursor:pointer;background:var(--surface2);transition:.15s}
.t-item:hover,.t-item.active{border-color:var(--blue);background:#1c2330}
.t-item .nm{font-weight:600;font-size:.9rem}
.t-item .meta{font-size:.72rem;color:var(--muted);margin-top:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.68rem;font-weight:600;margin-right:4px}
.b-run{background:#23863633;color:var(--green)}
.b-stop{background:#f8514933;color:var(--red)}
.b-ok{background:#23863633;color:var(--green)}
.b-wait{background:#6e768133;color:var(--muted)}
.b-deg{background:#d2992233;color:var(--yellow)}
.b-dead{background:#f8514933;color:var(--red)}
.detail-empty{color:var(--muted);padding:40px 10px;text-align:center}
.info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:.82rem}
.info-row:last-child{border:none}
.ik{color:var(--muted)}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:6px}
.dot.connected{background:var(--green)}
.dot.waiting{background:var(--muted)}
.dot.degraded{background:var(--yellow)}
.dot.dead,.dot.stopped{background:var(--red)}
.bw-row{margin:14px 0}
.bw-header{display:flex;justify-content:space-between;font-size:.8rem;margin-bottom:6px}
.bar-track{background:#0d1117;border:1px solid var(--border);border-radius:6px;height:10px;overflow:hidden}
.bar-fill{height:100%;width:0;transition:width .6s ease}
.bar-fill.dl{background:linear-gradient(90deg,#6e40c9,var(--purple))}
.bar-fill.ul{background:linear-gradient(90deg,#1158c7,var(--blue))}
.btn{margin-top:12px;width:100%;padding:10px;border:1px solid var(--border);border-radius:8px;
background:var(--surface2);color:var(--text);cursor:pointer;font-size:.85rem}
.btn:hover{border-color:var(--blue)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.err{color:var(--red);font-size:.78rem;margin-top:8px;min-height:1.2em}
.meta-top{font-size:.72rem;color:var(--muted);margin-bottom:12px}
</style>
</head>
<body>
<div class="wrap">
  <h1>virlink control panel</h1>
  <p class="sub">All tunnels · status · bandwidth test — single port, no overlay links</p>
  <p class="meta-top" id="meta">Loading…</p>
  <div class="grid">
    <div class="card">
      <div class="card-title">Tunnels</div>
      <div class="tunnel-list" id="list"><p class="detail-empty">Loading…</p></div>
    </div>
    <div class="card">
      <div class="card-title">Details &amp; speed test</div>
      <div id="detail"><p class="detail-empty">Select a tunnel from the list</p></div>
    </div>
  </div>
</div>
<script>
let tunnels=[], selected=null, maxMbps=1000;

function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}
function badge(cls,t){return '<span class="badge '+cls+'">'+esc(t)+'</span>';}
function hsCls(h){
  if(h==='connected'||h==='n/a')return 'b-ok';
  if(h==='degraded')return 'b-deg';
  if(h==='dead'||h==='stopped')return 'b-dead';
  return 'b-wait';
}

async function loadList(){
  const r=await fetch('/api/tunnels');
  const d=await r.json();
  tunnels=d.tunnels||[];
  document.getElementById('meta').textContent='Updated '+new Date().toLocaleTimeString()+' · '+d.count+' tunnel(s)';
  const el=document.getElementById('list');
  if(!tunnels.length){el.innerHTML='<p class="detail-empty">No tunnels found in configs</p>';return;}
  el.innerHTML=tunnels.map(t=>{
    const act=selected===t.name?' active':'';
    const svc=t.service||'?';
    const svcC=svc==='running'?'b-run':'b-stop';
    return '<div class="t-item'+act+'" data-name="'+esc(t.name)+'" onclick="selectTunnel(\''+esc(t.name).replace(/'/g,"\\'")+'\')">'+
      '<div class="nm">'+esc(t.name)+'</div>'+
      '<div class="meta">'+esc(t.type)+' · '+esc(t.mode)+' · '+badge(svcC,svc)+' '+badge(hsCls(t.handshake),t.handshake||'?')+'</div></div>';
  }).join('');
}

async function selectTunnel(name){
  selected=name;
  await loadList();
  const t=tunnels.find(x=>x.name===name);
  if(!t){return;}
  const det=document.getElementById('detail');
  det.innerHTML='<p class="detail-empty">Loading '+esc(name)+'…</p>';
  let health=null, err='';
  if(t.service==='running'&&!t.bench_available&&t.handshake==='n/a'){
    err='Health probe disabled for this tunnel type';
  } else if(t.service==='running'){
    try{
      const hr=await fetch('/api/tunnel/'+encodeURIComponent(name)+'/health');
      health=await hr.json();
      if(health.error)err=health.error;
    }catch(e){err=String(e);}
  } else {
    err='Service not running (systemctl start virlink-'+name+')';
  }
  const hs=(health&&health.handshake)||t.handshake||'?';
  let html='<div class="info-row"><span class="ik">Tunnel</span><strong>'+esc(t.name)+'</strong></div>';
  html+='<div class="info-row"><span class="ik">Type</span>'+esc(t.type)+' / '+esc(t.mode)+'</div>';
  html+='<div class="info-row"><span class="ik">Service</span>'+badge(t.service==='running'?'b-run':'b-stop',t.service)+'</div>';
  html+='<div class="info-row"><span class="ik">Link</span><span class="dot '+esc(hs)+'"></span>'+esc(hs)+
    (health&&health.uptime?' <span style="color:var(--muted)">('+esc(health.uptime)+')</span>':'')+'</div>';
  html+='<div class="info-row"><span class="ik">Overlay</span>'+esc(t.overlay_ip)+' → '+esc(t.peer_ip)+'</div>';
  html+='<div class="info-row"><span class="ik">Public</span>'+esc(t.local_ip)+' ↔ '+esc(t.remote_ip)+'</div>';
  if(health&&health.interfaces&&health.interfaces.length){
    html+='<div style="margin-top:12px;font-size:.72rem;color:var(--muted)">Interface stats</div>';
    health.interfaces.forEach(i=>{
      html+='<div class="info-row"><span class="ik">'+esc(i.name)+'</span>↓ '+fmtB(i.rx_bytes)+' · ↑ '+fmtB(i.tx_bytes)+'</div>';
    });
  }
  if(t.service==='running'&&t.bench_available!==false&&t.handshake!=='n/a'){
    html+='<div style="margin-top:18px;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em">Bandwidth test (via tunnel)</div>';
    html+='<div class="bw-row"><div class="bw-header"><span>▼ Download</span><span id="dl-mbps">—</span></div><div class="bar-track"><div class="bar-fill dl" id="dl-bar"></div></div></div>';
    html+='<div class="bw-row"><div class="bw-header"><span>▲ Upload</span><span id="ul-mbps">—</span></div><div class="bar-track"><div class="bar-fill ul" id="ul-bar"></div></div></div>';
    html+='<button class="btn" id="bench-btn" onclick="runBench(\''+esc(name).replace(/'/g,"\\'")+'\')">▶ Run speed test (~15s)</button>';
    html+='<div class="err" id="bench-err"></div>';
    if(health&&health.last_bench){
      setTimeout(()=>showBench(health.last_bench),0);
    }
  }
  if(err)html+='<div class="err">'+esc(err)+'</div>';
  det.innerHTML=html;
}

function fmtB(n){
  n=+n||0;
  if(n<1024)return n+' B';
  if(n<1048576)return (n/1024).toFixed(1)+' KB';
  if(n<1073741824)return (n/1048576).toFixed(2)+' MB';
  return (n/1073741824).toFixed(2)+' GB';
}

function showBench(b){
  if(!b)return;
  const dl=b.download_mbps||0, ul=b.upload_mbps||0;
  maxMbps=Math.max(maxMbps,dl,ul,100)*1.1;
  const dm=document.getElementById('dl-mbps'), um=document.getElementById('ul-mbps');
  const db=document.getElementById('dl-bar'), ub=document.getElementById('ul-bar');
  if(dm){dm.textContent=dl?dl.toFixed(1)+' Mbps':'—';}
  if(um){um.textContent=ul?ul.toFixed(1)+' Mbps':'—';}
  if(db){db.style.width=Math.min(100,dl/maxMbps*100)+'%';}
  if(ub){ub.style.width=Math.min(100,ul/maxMbps*100)+'%';}
}

async function runBench(name){
  const btn=document.getElementById('bench-btn');
  const err=document.getElementById('bench-err');
  if(btn){btn.disabled=true;btn.textContent='Testing…';}
  if(err)err.textContent='';
  try{
    const r=await fetch('/api/tunnel/'+encodeURIComponent(name)+'/bench');
    const b=await r.json();
    if(b.error){if(err)err.textContent=b.error;return;}
    showBench(b);
  }catch(e){if(err)err.textContent=String(e);}
  finally{if(btn){btn.disabled=false;btn.textContent='▶ Run speed test (~15s)';}}
}

loadList();
setInterval(loadList,15000);
</script>
</body>
</html>`
