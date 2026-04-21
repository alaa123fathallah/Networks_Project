import threading       # to run the admin server in its own thread
import json            # to send JSON data to the dashboard
import os              # for reading files
from http.server import HTTPServer, BaseHTTPRequestHandler  # simple built-in web server

from config import (ADMIN_PORT, BLACKLIST_FILE, WHITELIST_FILE,
                     LOG_FILE, WHITELIST_MODE)  # admin-related settings
from cache import cache    # to read cache entries
from logger import logger  # for logging admin events

# ---------------------------------------------------------------------------
# Bonus I – Web-Based Admin Interface
# Serves a simple dashboard on ADMIN_PORT showing logs, cache, blacklist,
# whitelist, and basic proxy usage statistics.
# ---------------------------------------------------------------------------

# shared counters updated by proxy.py on every request
stats = {
    "total_requests": 0,       # total requests handled
    "blocked_requests": 0,     # requests blocked by filter
    "cache_hits": 0,           # responses served from cache
    "active_connections": 0,   # currently open client connections
    "bytes_transferred": 0,    # total response bytes sent to clients
}
stats_lock = threading.Lock()  # protects the stats dict from race conditions


def increment_stat(key: str, value: int = 1):
    """Thread-safe helper to bump a counter in the stats dict."""
    with stats_lock:
        stats[key] = stats.get(key, 0) + value  # add value to the counter


def get_stats() -> dict:
    """Return a snapshot of the current stats."""
    with stats_lock:
        return dict(stats)  # return a copy so the caller can't mutate it


def _read_file_lines(filepath: str) -> list:
    """Read non-comment, non-empty lines from a text file."""
    lines = []
    if not os.path.exists(filepath):  # file might not exist yet
        return lines
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  # skip comments and blanks
                lines.append(line)
    return lines


def _read_recent_logs(max_lines: int = 100) -> list:
    """Return the last *max_lines* lines from the log file."""
    if not os.path.exists(LOG_FILE):  # no log file yet
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        all_lines = f.readlines()  # read all log lines
    return [l.rstrip() for l in all_lines[-max_lines:]]  # return the most recent ones


# ---- HTML template for the dashboard ----

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Proxy Admin Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
  h1 { color: #333; }
  h2 { color: #555; margin-top: 30px; }
  .card { background: #fff; border-radius: 8px; padding: 16px; margin: 10px 0;
          box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                 gap: 12px; }
  .stat-box { text-align: center; padding: 12px; }
  .stat-box .number { font-size: 28px; font-weight: bold; color: #2563eb; }
  .stat-box .label { font-size: 13px; color: #666; margin-top: 4px; }
  table { width: 100%%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; }
  th { background: #f9f9f9; font-weight: 600; }
  .log-box { max-height: 350px; overflow-y: auto; background: #1e1e1e; color: #d4d4d4;
             padding: 12px; font-family: monospace; font-size: 12px; border-radius: 6px;
             white-space: pre-wrap; word-break: break-all; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
  .badge-on  { background: #dcfce7; color: #166534; }
  .badge-off { background: #fee2e2; color: #991b1b; }
  button { padding: 6px 16px; border: none; border-radius: 4px; cursor: pointer;
           background: #2563eb; color: #fff; font-size: 13px; }
  button:hover { background: #1d4ed8; }
</style>
</head>
<body>

<h1>Proxy Admin Dashboard</h1>

<!-- Stats Section -->
<div class="card">
  <h2 style="margin-top:0">Proxy Statistics</h2>
  <div class="stats-grid" id="stats-grid"></div>
</div>

<!-- Cache Section -->
<div class="card">
  <h2 style="margin-top:0">Cache Entries
    <span style="font-size:14px; color:#888;" id="cache-count"></span>
  </h2>
  <table>
    <thead><tr><th>URL</th><th>Size</th><th>TTL Remaining</th></tr></thead>
    <tbody id="cache-body"></tbody>
  </table>
</div>

<!-- Blacklist / Whitelist Section -->
<div class="card">
  <h2 style="margin-top:0">Blacklist / Whitelist</h2>
  <p>Mode: <span id="filter-mode" class="badge"></span></p>
  <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
    <div>
      <h3>Blacklist</h3>
      <ul id="blacklist"></ul>
    </div>
    <div>
      <h3>Whitelist</h3>
      <ul id="whitelist"></ul>
    </div>
  </div>
</div>

<!-- Logs Section -->
<div class="card">
  <h2 style="margin-top:0">Recent Logs</h2>
  <div class="log-box" id="log-box"></div>
</div>

<script>
// fetch data from the API and populate the dashboard
async function refresh() {
  try {
    const r = await fetch("/api/data");          // get all dashboard data
    const d = await r.json();

    // --- stats ---
    const grid = document.getElementById("stats-grid");
    const labels = {
      total_requests: "Total Requests", blocked_requests: "Blocked",
      cache_hits: "Cache Hits", active_connections: "Active Connections",
      bytes_transferred: "Bytes Transferred", cache_size: "Cached Items"
    };
    d.stats.cache_size = d.cache.length;         // add cache size to stats
    grid.innerHTML = "";
    for (const [k, v] of Object.entries(labels)) {
      let val = d.stats[k] !== undefined ? d.stats[k] : 0;
      if (k === "bytes_transferred") val = (val / 1024).toFixed(1) + " KB";
      grid.innerHTML += '<div class="stat-box"><div class="number">' + val +
                        '</div><div class="label">' + v + '</div></div>';
    }

    // --- cache ---
    document.getElementById("cache-count").textContent = "(" + d.cache.length + ")";
    const cb = document.getElementById("cache-body");
    cb.innerHTML = "";
    d.cache.forEach(function(e) {
      cb.innerHTML += "<tr><td>" + e.key + "</td><td>" +
        (e.size / 1024).toFixed(1) + " KB</td><td>" + e.ttl_remaining + "s</td></tr>";
    });

    // --- filter lists ---
    const fm = document.getElementById("filter-mode");
    fm.textContent = d.whitelist_mode ? "Whitelist" : "Blacklist";
    fm.className = "badge " + (d.whitelist_mode ? "badge-on" : "badge-off");

    document.getElementById("blacklist").innerHTML =
      d.blacklist.map(function(h){ return "<li>" + h + "</li>"; }).join("") || "<li>empty</li>";
    document.getElementById("whitelist").innerHTML =
      d.whitelist.map(function(h){ return "<li>" + h + "</li>"; }).join("") || "<li>empty</li>";

    // --- logs ---
    document.getElementById("log-box").textContent = d.logs.join("\\n");
  } catch(err) { console.error("Dashboard refresh failed:", err); }
}

refresh();                        // load data on page open
setInterval(refresh, 3000);       // auto-refresh every 3 seconds
</script>
</body>
</html>
"""


class AdminHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the admin dashboard."""

    def log_message(self, format, *args):
        pass  # suppress default HTTP server logs to keep the console clean

    def do_GET(self):
        if self.path == "/" or self.path == "/dashboard":  # serve the HTML page
            self._send_html(DASHBOARD_HTML)
        elif self.path == "/api/data":  # serve JSON data for the dashboard
            self._send_json(self._build_data())
        else:
            self.send_error(404)  # unknown path

    def _build_data(self) -> dict:
        """Collect all data the dashboard needs into one dict."""
        return {
            "stats": get_stats(),                          # proxy usage counters
            "cache": cache.entries(),                       # cached responses
            "blacklist": _read_file_lines(BLACKLIST_FILE),  # blocked domains
            "whitelist": _read_file_lines(WHITELIST_FILE),  # allowed domains
            "whitelist_mode": WHITELIST_MODE,               # current filter mode
            "logs": _read_recent_logs(100),                 # last 100 log lines
        }

    def _send_html(self, html: str):
        body = html.encode("utf-8")             # encode to bytes
        self.send_response(200)                  # 200 OK
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)                   # send the page

    def _send_json(self, data: dict):
        body = json.dumps(data).encode("utf-8")  # serialize to JSON bytes
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_admin_server(port: int = ADMIN_PORT):
    """Start the admin dashboard HTTP server in a daemon thread."""
    server = HTTPServer(("0.0.0.0", port), AdminHandler)  # bind to all interfaces
    thread = threading.Thread(target=server.serve_forever, daemon=True)  # run in background
    thread.start()
    logger.info(f"Admin dashboard running on http://127.0.0.1:{port}")
