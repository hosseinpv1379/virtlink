package webpanel

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>virlink — tunnels</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#6e7681;
--green:#3fb950;--yellow:#d29922;--red:#f85149;--blue:#58a6ff;
--font:ui-sans-serif,system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);padding:24px}
a{color:var(--blue)}
h1{font-size:1.4rem;margin-bottom:4px}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:20px}
.meta{color:var(--muted);font-size:.75rem;margin-bottom:16px}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
th,td{padding:12px 14px;text-align:left;border-bottom:1px solid var(--border);font-size:.85rem}
th{background:#21262d;color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.08em}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.72rem;font-weight:600}
.b-run{background:#23863633;color:var(--green)}
.b-stop{background:#f8514933;color:var(--red)}
.b-fail{background:#f8514933;color:var(--red)}
.b-wait{background:#6e768133;color:var(--muted)}
.b-ok{background:#23863633;color:var(--green)}
.b-deg{background:#d2992233;color:var(--yellow)}
.b-dead{background:#f8514933;color:var(--red)}
.empty{padding:40px;text-align:center;color:var(--muted)}
</style>
</head>
<body>
<h1>virlink tunnels</h1>
<p class="sub">All tunnels detected from configs directory</p>
<p class="meta" id="meta">Loading…</p>
<div id="root"><p class="empty">Loading tunnels…</p></div>
<script>
async function load(){
  try{
    const r=await fetch('/api/tunnels');
    const d=await r.json();
    document.getElementById('meta').textContent='Updated '+new Date().toLocaleTimeString()+' · '+d.count+' tunnel(s)';
    if(!d.tunnels||!d.tunnels.length){
      document.getElementById('root').innerHTML='<p class="empty">No tunnels configured yet. Use virlink-setup to create one.</p>';
      return;
    }
    let h='<table><thead><tr><th>Name</th><th>Type</th><th>Mode</th><th>Service</th><th>Link</th><th>Overlay</th><th>Peer</th><th>Remote</th><th>Panel</th></tr></thead><tbody>';
    for(const t of d.tunnels){
      const svc=t.service||'?';
      const svcCls=svc==='running'?'b-run':(svc==='stopped'?'b-stop':'b-fail');
      const hs=t.handshake||'?';
      let hsCls='b-wait';
      if(hs==='connected'||hs==='n/a')hsCls='b-ok';
      else if(hs==='degraded')hsCls='b-deg';
      else if(hs==='dead'||hs==='stopped')hsCls='b-dead';
      const panel=t.panel_url?('<a href="'+t.panel_url+'" target="_blank" rel="noopener">open</a>'):'—';
      h+='<tr><td><strong>'+esc(t.name)+'</strong></td><td>'+esc(t.type)+'</td><td>'+esc(t.mode)+'</td>';
      h+='<td><span class="badge '+svcCls+'">'+esc(svc)+'</span></td>';
      h+='<td><span class="badge '+hsCls+'">'+esc(hs)+'</span>'+(t.uptime?' <span style="color:var(--muted)">'+esc(t.uptime)+'</span>':'')+'</td>';
      h+='<td>'+esc(t.overlay_ip)+'</td><td>'+esc(t.peer_ip)+'</td><td>'+esc(t.remote_ip)+'</td><td>'+panel+'</td></tr>';
    }
    h+='</tbody></table>';
    document.getElementById('root').innerHTML=h;
  }catch(e){
    document.getElementById('root').innerHTML='<p class="empty">Failed to load: '+esc(String(e))+'</p>';
  }
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}
load();
setInterval(load,10000);
</script>
</body>
</html>`
