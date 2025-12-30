bash -c "$(cat << 'EOF'
set -euo pipefail
echo '=== CIBE SHIELD UI FIX CONNECTION ==='

# Stop existing processes
pkill -f "node.*server.js" 2>/dev/null || true
sleep 2

# Ensure directories exist
mkdir -p /opt/dbot/ui
mkdir -p /usr/local/bin

IFACE=$(ip route get 1 2>/dev/null | awk '{print $5;exit}' || echo "eth0")

# =========================
# STATS SCRIPT (SIMPLIFIED)
# =========================
cat > /usr/local/bin/cibe-stats.sh << 'ST'
#!/bin/bash
IFACE=$(ip route get 1 2>/dev/null | awk '{print $5;exit}' || echo "eth0")

RXB=/sys/class/net/$IFACE/statistics/rx_bytes
TXB=/sys/class/net/$IFACE/statistics/tx_bytes
RXP=/sys/class/net/$IFACE/statistics/rx_packets
RXD=/sys/class/net/$IFACE/statistics/rx_dropped

if [ ! -f "$RXB" ]; then
  echo '{"pps":0,"inbound_mbps":0,"outbound_mbps":0,"total_mb":0,"xdp_status":"offline","ping_ms":0,"filtered_pct":0,"ddos":false,"interface":"'$IFACE'"}'
  exit 0
fi

rxb1=$(cat $RXB 2>/dev/null || echo 0)
txb1=$(cat $TXB 2>/dev/null || echo 0)
rxp1=$(cat $RXP 2>/dev/null || echo 0)
rxd1=$(cat $RXD 2>/dev/null || echo 0)

sleep 1

rxb2=$(cat $RXB 2>/dev/null || echo 0)
txb2=$(cat $TXB 2>/dev/null || echo 0)
rxp2=$(cat $RXP 2>/dev/null || echo 0)
rxd2=$(cat $RXD 2>/dev/null || echo 0)

drx=$((rxb2-rxb1))
dtx=$((txb2-txb1))
dp=$((rxp2-rxp1))
dd=$((rxd2-rxd1))

[ "$drx" -lt 0 ] && drx=0
[ "$dtx" -lt 0 ] && dtx=0
[ "$dp" -lt 0 ] && dp=0
[ "$dd" -lt 0 ] && dd=0

in_mbps=$(awk "BEGIN{printf \"%.2f\", ($drx*8)/1000000}")
out_mbps=$(awk "BEGIN{printf \"%.2f\", ($dtx*8)/1000000}")
total_mb=$(awk "BEGIN{printf \"%.2f\", $rxb2/1048576}")

filter_pct=0
if [ "$dp" -gt 0 ]; then
  filter_pct=$(awk "BEGIN{printf \"%.2f\", ($dd/($dp+$dd))*100}")
fi

xdp_status="offline"
ip -details link show $IFACE 2>/dev/null | grep -q xdp && xdp_status="online"

ping_ms=$(ping -c1 -W1 8.8.8.8 2>/dev/null | awk -F'time=' '/time=/{print $2}' | awk '{print $1}' || echo 0)
[ -z "$ping_ms" ] && ping_ms=0

ddos=false
attack_type="None"
[ "$dp" -gt 5000 ] && ddos=true && attack_type="High PPS"

cat << JSON
{
  "pps": $dp,
  "inbound_mbps": $in_mbps,
  "outbound_mbps": $out_mbps,
  "total_mb": $total_mb,
  "xdp_status": "$xdp_status",
  "ping_ms": $ping_ms,
  "filtered_pct": $filter_pct,
  "ddos": $ddos,
  "attack_type": "$attack_type",
  "interface": "$IFACE"
}
JSON
ST
chmod +x /usr/local/bin/cibe-stats.sh

# Test stats script
echo "Testing stats script..."
/usr/local/bin/cibe-stats.sh || echo "Stats script test completed"

# =========================
# UI SERVER (FIXED)
# =========================
cat > /opt/dbot/ui/server.js << 'JS'
const express = require('express')
const { exec } = require('child_process')
const app = express()

app.get('/', (_, res) => res.send(`<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIBE SHIELD</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;min-height:100vh}
nav{display:flex;justify-content:space-between;align-items:center;padding:20px;background:#1e293b;border-bottom:2px solid #334155}
.logo{font-size:24px;font-weight:700;color:#3b82f6;text-transform:uppercase}
.status{display:flex;align-items:center;gap:8px;font-weight:600;padding:8px 16px;border-radius:8px;background:#334155}
.status.online{color:#10b981;border:2px solid #10b981}
.status.offline{color:#ef4444;border:2px solid #ef4444}
.status:before{content:'';width:8px;height:8px;border-radius:50%;background:currentColor;animation:blink 1.5s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
.container{max-width:1400px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:20px}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;transition:transform 0.2s}
.card:hover{transform:translateY(-2px)}
.card-label{font-size:12px;color:#94a3b8;text-transform:uppercase;margin-bottom:8px}
.card-value{font-size:32px;font-weight:700;color:#3b82f6}
.card-unit{font-size:14px;color:#64748b;margin-left:4px}
.chart-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px}
.alert{background:linear-gradient(135deg,#7f1d1d,#991b1b);border:2px solid #dc2626;border-radius:12px;padding:20px;animation:pulse 2s infinite;margin-bottom:20px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.9}}
.alert-title{font-size:20px;font-weight:700;color:#fecaca;margin-bottom:12px}
.alert-details{color:#fca5a5;line-height:1.6}
.info{background:#334155;padding:12px 20px;border-radius:8px;font-size:13px;color:#94a3b8;display:flex;justify-content:space-between}
</style>
</head>
<body>
<nav>
  <div class="logo">🛡️ CIBE SHIELD</div>
  <div id="xdp" class="status offline">LOADING</div>
</nav>
<div class="container">
  <div class="grid">
    <div class="card">
      <div class="card-label">Total Traffic</div>
      <div class="card-value" id="total">0<span class="card-unit">MB</span></div>
    </div>
    <div class="card">
      <div class="card-label">Inbound</div>
      <div class="card-value" id="in">0<span class="card-unit">Mbps</span></div>
    </div>
    <div class="card">
      <div class="card-label">Outbound</div>
      <div class="card-value" id="out">0<span class="card-unit">Mbps</span></div>
    </div>
    <div class="card">
      <div class="card-label">Latency</div>
      <div class="card-value" id="ping">0<span class="card-unit">ms</span></div>
    </div>
    <div class="card">
      <div class="card-label">PPS</div>
      <div class="card-value" id="pps">0<span class="card-unit">pkt/s</span></div>
    </div>
    <div class="card">
      <div class="card-label">Filtered</div>
      <div class="card-value" id="filter">0<span class="card-unit">%</span></div>
    </div>
  </div>
  <div id="ddos"></div>
  <div class="chart-card">
    <canvas id="chart"></canvas>
  </div>
  <div class="info">
    <span id="iface">Interface: -</span>
    <span id="last">Last: -</span>
  </div>
</div>
<script>
const chart = new Chart(document.getElementById('chart'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      {label: 'PPS', data: [], borderColor: '#3b82f6', borderWidth: 2, tension: 0.4},
      {label: 'In (Mbps)', data: [], borderColor: '#10b981', borderWidth: 2, tension: 0.4},
      {label: 'Out (Mbps)', data: [], borderColor: '#f59e0b', borderWidth: 2, tension: 0.4}
    ]
  },
  options: {
    responsive: true,
    plugins: {legend: {labels: {color: '#e2e8f0'}}},
    scales: {
      x: {display: false},
      y: {ticks: {color: '#94a3b8'}, grid: {color: '#334155'}}
    }
  }
})

async function update(){
  try {
    const r = await fetch('/stats')
    const j = await r.json()
    
    document.getElementById('total').innerHTML = (j.total_mb > 1024 ? (j.total_mb/1024).toFixed(2) + '<span class="card-unit">GB</span>' : j.total_mb.toFixed(2) + '<span class="card-unit">MB</span>')
    document.getElementById('in').innerHTML = j.inbound_mbps.toFixed(2) + '<span class="card-unit">Mbps</span>'
    document.getElementById('out').innerHTML = j.outbound_mbps.toFixed(2) + '<span class="card-unit">Mbps</span>'
    document.getElementById('ping').innerHTML = j.ping_ms + '<span class="card-unit">ms</span>'
    document.getElementById('pps').innerHTML = j.pps + '<span class="card-unit">pkt/s</span>'
    document.getElementById('filter').innerHTML = j.filtered_pct.toFixed(2) + '<span class="card-unit">%</span>'
    
    const xdp = document.getElementById('xdp')
    xdp.className = 'status ' + j.xdp_status
    xdp.textContent = j.xdp_status.toUpperCase()
    
    chart.data.labels.push('')
    chart.data.datasets[0].data.push(j.pps)
    chart.data.datasets[1].data.push(j.inbound_mbps)
    chart.data.datasets[2].data.push(j.outbound_mbps)
    
    if (chart.data.labels.length > 30) {
      chart.data.labels.shift()
      chart.data.datasets.forEach(d => d.data.shift())
    }
    chart.update('none')
    
    document.getElementById('ddos').innerHTML = j.ddos ? '<div class="alert"><div class="alert-title">⚠️ DDoS Detected</div><div class="alert-details">Type: <strong>' + j.attack_type + '</strong><br>PPS: <strong>' + j.pps + '</strong><br>Filtered: <strong>' + j.filtered_pct.toFixed(2) + '%</strong></div></div>' : ''
    
    document.getElementById('iface').textContent = 'Interface: ' + j.interface
    document.getElementById('last').textContent = 'Last: ' + new Date().toLocaleTimeString()
  } catch (e) {
    console.error('Update error:', e)
  }
}

update()
setInterval(update, 1000)
</script>
</body>
</html>`))

app.get('/stats', (req, res) => {
  exec('/usr/local/bin/cibe-stats.sh', { timeout: 3000 }, (err, stdout, stderr) => {
    if (err) {
      console.error('Stats error:', err)
      return res.json({
        pps: 0, inbound_mbps: 0, outbound_mbps: 0, total_mb: 0,
        xdp_status: 'offline', ping_ms: 0, filtered_pct: 0,
        ddos: false, interface: 'unknown'
      })
    }
    try {
      res.json(JSON.parse(stdout))
    } catch (e) {
      res.json({
        pps: 0, inbound_mbps: 0, outbound_mbps: 0, total_mb: 0,
        xdp_status: 'offline', ping_ms: 0, filtered_pct: 0,
        ddos: false, interface: 'unknown'
      })
    }
  })
})

const PORT = 8989
app.listen(PORT, '0.0.0.0', () => {
  console.log('CIBE Shield UI listening on port ' + PORT)
})
JS

# =========================
# START SERVER DIRECTLY
# =========================
echo "Starting UI server..."
cd /opt/dbot/ui

# Check if node and express available
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js not installed!"
    echo "Install with: apt install -y nodejs npm"
    exit 1
fi

if [ ! -d "node_modules/express" ]; then
    echo "Installing Express..."
    npm install express 2>/dev/null || {
        echo "Creating package.json..."
        echo '{"dependencies":{"express":"^4.18.0"}}' > package.json
        npm install
    }
fi

# Start server
nohup node server.js > /tmp/cibe-ui.log 2>&1 &
SERVER_PID=$!

sleep 3

# Check if server is running
if ps -p $SERVER_PID > /dev/null; then
    echo ""
    echo "=== ✓ CIBE SHIELD UI STARTED ==="
    echo "PID: $SERVER_PID"
    echo "Port: 8989"
    echo "Log: /tmp/cibe-ui.log"
    echo ""
    echo "Access: http://$(hostname -I | awk '{print $1}'):8989"
    echo ""
    echo "Check logs: tail -f /tmp/cibe-ui.log"
else
    echo ""
    echo "=== ERROR: Server failed to start ==="
    echo "Check log: cat /tmp/cibe-ui.log"
    exit 1
fi
EOF
)"
