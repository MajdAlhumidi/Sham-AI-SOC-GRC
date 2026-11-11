"""Original Agent dashboard restored from the pre-upgrade deployment backup."""
import html
import json
from fastapi.responses import HTMLResponse

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI-Agent Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #070A10; --surface: #0D121C; --surface-2: #111B2A; --deep: #060910;
      --border: #1C2536; --text: #E6EBF2; --text-2: #B4BFD0; --muted: #8A97AB;
      --cyan: #4CC9F0; --red: #FF7A87; --amber: #FFA94D; --yellow: #F5D547; --green: #3DDC97;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'IBM Plex Sans', system-ui, sans-serif; min-height: 100vh; display: flex; flex-direction: column; }
    .mono { font-family: 'IBM Plex Mono', monospace; }
    button { font-family: inherit; cursor: pointer; }
    button:focus-visible, input:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }

    header { display: flex; flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between; padding: 14px 28px; border-bottom: 1px solid var(--border); background: #0A0F18; position: sticky; top: 0; z-index: 50; }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-title { font-weight: 600; font-size: 15px; letter-spacing: .08em; }
    .brand-sub { font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--muted); }
    .head-right { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; font-family: 'IBM Plex Mono', monospace; font-size: 12px; }
    .live { display: inline-flex; align-items: center; gap: 8px; border: 1px solid #1F5E48; color: var(--green); padding: 5px 12px; border-radius: 4px; }
    .live i { width: 7px; height: 7px; border-radius: 50%; background: var(--green); }
    .clock { color: var(--muted); }

    .layout { padding: 22px 28px; display: flex; flex-direction: column; gap: 18px; flex: 1; width: 100%; max-width: 1700px; margin: 0 auto; }
    .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; }
    .kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px 18px; }
    .kpi .l { font-size: 11px; letter-spacing: .08em; color: var(--muted); text-transform: uppercase; }
    .kpi .v { font-family: 'IBM Plex Mono', monospace; font-size: 30px; font-weight: 600; margin-top: 6px; }

    .toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; }
    .search { display: flex; align-items: center; gap: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0 12px; min-width: 280px; flex: 1; max-width: 420px; }
    .search input { background: transparent; border: 0; outline: 0; color: var(--text); font-family: 'IBM Plex Mono', monospace; font-size: 12px; height: 44px; width: 100%; }
    .search input::placeholder { color: #5E6B80; }
    .pills { display: flex; flex-wrap: wrap; gap: 8px; }
    .pill { min-height: 44px; padding: 0 16px; border-radius: 4px; border: 1px solid var(--border); background: #0A0F18; color: var(--text-2); font-size: 12px; }
    .pill:hover { color: #fff; }
    .pill.active { border-color: var(--cyan); background: #0F2A38; color: var(--cyan); font-weight: 600; }
    .sync { min-height: 44px; padding: 0 16px; border-radius: 4px; border: 1px solid var(--border); background: #0A0F18; color: var(--text); font-size: 12px; font-weight: 600; }

    .workspace { display: grid; grid-template-columns: repeat(auto-fit, minmax(440px, 1fr)); gap: 16px; align-items: start; }
    .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
    .panel-head { display: flex; justify-content: space-between; padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 11px; letter-spacing: .08em; color: var(--muted); text-transform: uppercase; }
    .scroll-x { overflow: auto; max-height: 560px; }
    table { width: 100%; border-collapse: collapse; min-width: 680px; font-size: 12px; }
    th { position: sticky; top: 0; background: #0D121C; text-align: left; color: var(--muted); font-size: 10.5px; letter-spacing: .07em; font-weight: 500; padding: 10px 12px; border-bottom: 1px solid var(--border); text-transform: uppercase; }
    td { padding: 11px 12px; border-top: 1px solid var(--border); white-space: nowrap; }
    tbody tr { cursor: pointer; }
    tbody tr:hover { background: #0F1826; }
    tr.selected { background: var(--surface-2) !important; box-shadow: inset 3px 0 0 var(--cyan); }
    .rule-cell { max-width: 240px; overflow: hidden; text-overflow: ellipsis; color: var(--text-2); }

    .sev { font-family: 'IBM Plex Mono', monospace; font-weight: 600; }
    .sev-crit { color: var(--red); } .sev-high { color: var(--amber); } .sev-med { color: var(--yellow); } .sev-low { color: var(--green); }

    .badge { display: inline-block; font-family: 'IBM Plex Mono', monospace; font-size: 11px; font-weight: 600; padding: 4px 9px; border-radius: 4px; text-transform: uppercase; border: 1px solid; }
    .badge-tp { color: var(--red); border-color: #6E2A33; background: #2A1217; }
    .badge-fp { color: var(--green); border-color: #1F5E48; background: #0E2A21; }
    .badge-susp { color: var(--yellow); border-color: #6B5C1B; background: #2A2410; }

    .inspector { padding: 18px; display: flex; flex-direction: column; gap: 16px; }
    .insp-head { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 10px; border-bottom: 1px solid var(--border); padding-bottom: 14px; }
    .insp-id { font-family: 'IBM Plex Mono', monospace; font-size: 16px; font-weight: 600; word-break: break-all; }
    .insp-rule { font-size: 12.5px; color: var(--text-2); margin-top: 4px; }
    .grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }
    .art { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; }
    .art .al { font-size: 10px; letter-spacing: .07em; color: var(--muted); margin-bottom: 4px; text-transform: uppercase; }
    .art .av { font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; word-break: break-all; }
    .report { background: var(--deep); border: 1px solid var(--border); border-radius: 6px; padding: 14px; }
    .report-title { font-size: 11px; letter-spacing: .08em; color: var(--cyan); margin-bottom: 8px; text-transform: uppercase; }
    .report-text { font-family: 'IBM Plex Mono', monospace; font-size: 12px; line-height: 1.65; white-space: pre-wrap; max-height: 260px; overflow-y: auto; }
    .foot { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px; border: 1px solid var(--border); background: var(--bg); border-radius: 4px; padding: 9px 12px; font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--muted); }
    .foot span span { color: var(--text-2); }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#4CC9F0" stroke-width="1.8" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>
      <div>
        <div class="brand-title">AI-AGENT DASHBOARD</div>
        <div class="brand-sub">Autonomous triage &amp; containment console</div>
      </div>
    </div>
    <div class="head-right">
      <span class="live"><i></i>STREAM ACTIVE</span>
      <span class="clock" id="clock-display">--:--:-- UTC</span>
    </div>
  </header>

  <main class="layout">

    <section class="kpis">
      <div class="kpi"><div class="l">Ingested Incidents</div><div class="v" id="metric-total">__METRIC_TOTAL__</div></div>
      <div class="kpi"><div class="l">Confirmed Threats (TP)</div><div class="v" id="metric-tp" style="color: var(--red);">__METRIC_TP__</div></div>
      <div class="kpi"><div class="l">Needs Review</div><div class="v" id="metric-review" style="color: var(--yellow);">__METRIC_REVIEW__</div></div>
      <div class="kpi"><div class="l">Filtered False Positives</div><div class="v" id="metric-fp" style="color: var(--green);">__METRIC_FP__</div></div>
      <div class="kpi"><div class="l">Total Mitigated</div><div class="v" id="metric-contained" style="color: var(--cyan);">__METRIC_CONTAINED__</div></div>
    </section>

    <section class="toolbar">
      <label class="search">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#8A97AB" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.5-4.5"/></svg>
        <input type="text" id="search-input" aria-label="Search incidents" placeholder="Case ID, host, IP, user, rule" oninput="handleSearch()">
      </label>
      <div class="pills">
        <button class="pill active" data-filter="All" onclick="setFilter('All')">All</button>
        <button class="pill" data-filter="Critical TP" onclick="setFilter('Critical TP')">Critical TP</button>
        <button class="pill" data-filter="Suspicious / Review" onclick="setFilter('Suspicious / Review')">Needs review</button>
        <button class="pill" data-filter="Benign/FP" onclick="setFilter('Benign/FP')">Benign / FP</button>
      </div>
      <button class="sync" onclick="location.reload()">Sync DB</button>
    </section>

    <section class="workspace">

      <div class="panel">
        <div class="panel-head">
          <span>Triage Feed (<span id="visible-count">__METRIC_TOTAL__</span>)</span>
          <span>Click a row to inspect</span>
        </div>
        <div class="scroll-x">
          <table>
            <thead>
              <tr><th>Severity</th><th>Case ID</th><th>Time</th><th>Host</th><th>Rule</th><th>Verdict</th></tr>
            </thead>
            <tbody id="incidents-tbody">
__TABLE_ROWS__
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel inspector" id="inspector-card">
        <div class="insp-head">
          <div>
            <div class="insp-id" id="insp-id">__INITIAL_ID__</div>
            <div class="insp-rule" id="insp-rule">__INITIAL_RULE__</div>
          </div>
          <div id="insp-verdict-badge">__INITIAL_VERDICT_BADGE__</div>
        </div>

        <div class="grid2">
          <div class="art"><div class="al">Target Host</div><div class="av" id="insp-host">__INITIAL_HOST__</div></div>
          <div class="art"><div class="al">Source IP</div><div class="av" id="insp-src">__INITIAL_SRC__</div></div>
          <div class="art"><div class="al">User Account</div><div class="av" id="insp-user">__INITIAL_USER__</div></div>
          <div class="art"><div class="al">Containment</div><div class="av" id="insp-containment" style="color: var(--cyan);">__INITIAL_CONTAINMENT__</div></div>
        </div>

        <div class="report">
          <div class="report-title">AI Analyst Investigation Notes</div>
          <div class="report-text" id="insp-details">__INITIAL_DETAILS__</div>
        </div>

        <div class="foot">
          <span>Agent: <span id="insp-provider">__INITIAL_PROVIDER__</span> (<span id="insp-model">__INITIAL_MODEL__</span>)</span>
          <span>Fallback: <span id="insp-fallback">__INITIAL_FALLBACK__</span></span>
        </div>
      </div>

    </section>
  </main>

  <script>
    const allIncidents = __JSON_DATA__;
    let currentFilter = "All";
    let searchQuery = "";

    function updateClock() {
      document.getElementById('clock-display').innerText = new Date().toUTCString().slice(17, 25) + " UTC";
    }
    setInterval(updateClock, 1000);
    updateClock();

    function badgeClass(v) {
      v = String(v || '').toLowerCase();
      if (v.includes('critical') || v.includes('tp')) return 'badge-tp';
      if (v.includes('benign') || v.includes('fp')) return 'badge-fp';
      return 'badge-susp';
    }

    function selectIncidentByIndex(idx) {
      const item = allIncidents[idx];
      if (!item) return;

      document.querySelectorAll('#incidents-tbody tr').forEach(tr => tr.classList.remove('selected'));
      const row = document.getElementById('row-' + idx);
      if (row) row.classList.add('selected');

      document.getElementById('insp-id').innerText = item.case_id;
      document.getElementById('insp-rule').innerText = (item.rule_name || "Security Alert") + " [Severity Level " + (item.level || 0) + "]";
      const v = String(item.verdict || '');
      document.getElementById('insp-verdict-badge').innerHTML = '<span class="badge ' + badgeClass(v) + '">' + v.replace(/</g, '&lt;') + '</span>';
      document.getElementById('insp-host').innerText = item.host_agent || "local-agent";
      document.getElementById('insp-src').innerText = item.source_ip || "N/A";
      document.getElementById('insp-user').innerText = item.user || "N/A";
      document.getElementById('insp-containment').innerText = item.containment || "Not executed";
      document.getElementById('insp-details').innerText = item.details || "No investigation notes recorded.";
      document.getElementById('insp-provider').innerText = item.llm_provider || "unknown";
      document.getElementById('insp-model').innerText = item.llm_model || "unknown";
      const fb = item.fallback_used === true ? "Enabled" : (item.fallback_used === false ? "None" : "N/A");
      document.getElementById('insp-fallback').innerText = fb;
    }

    function setFilter(filter) {
      currentFilter = filter;
      document.querySelectorAll('.pill').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
      });
      applyFilters();
    }

    function handleSearch() {
      searchQuery = document.getElementById('search-input').value.toLowerCase().trim();
      applyFilters();
    }

    function applyFilters() {
      let count = 0;
      allIncidents.forEach((inc, idx) => {
        const row = document.getElementById('row-' + idx);
        if (!row) return;
        const matchesFilter = (currentFilter === "All") || (inc.verdict === currentFilter) ||
          (currentFilter === "Critical TP" && inc.verdict.includes("Critical")) ||
          (currentFilter === "Benign/FP" && inc.verdict.includes("Benign"));
        const blob = (inc.case_id + " " + inc.host_agent + " " + inc.source_ip + " " + inc.rule_name + " " + inc.user).toLowerCase();
        const matchesSearch = !searchQuery || blob.includes(searchQuery);
        if (matchesFilter && matchesSearch) { row.style.display = ""; count++; }
        else { row.style.display = "none"; }
      });
      document.getElementById('visible-count').innerText = count;
    }

    function connectWS() {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(proto + '//' + window.location.host + '/ws');
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "NEW_ALERT") { location.reload(); }
      };
      ws.onclose = () => setTimeout(connectWS, 3000);
    }
    connectWS();
  </script>
</body>
</html>"""

def verdict_badge_class(v: str) -> str:
    v = v.lower()
    if "critical" in v or "tp" in v:
        return "badge-tp"
    if "benign" in v or "fp" in v:
        return "badge-fp"
    return "badge-susp"

def severity_cell(lvl: int) -> str:
    if lvl >= 10:
        return f'<span class="sev sev-crit">▲ CRIT {lvl}</span>'
    if lvl >= 8:
        return f'<span class="sev sev-high">■ HIGH {lvl}</span>'
    if lvl >= 5:
        return f'<span class="sev sev-med">◆ MED {lvl}</span>'
    return f'<span class="sev sev-low">● LOW {lvl}</span>'

def render_dashboard(incidents):
    total = len(incidents)
    tp_count = sum(1 for x in incidents if "critical" in x["verdict"].lower() or "tp" in x["verdict"].lower())
    fp_count = sum(1 for x in incidents if "benign" in x["verdict"].lower() or "fp" in x["verdict"].lower())
    review_count = sum(1 for x in incidents if "suspicious" in x["verdict"].lower())
    contained_count = sum(1 for x in incidents if x["containment"].strip().lower() == "executed & verified")

    rows = []
    for i, inc in enumerate(incidents):
        v = inc["verdict"]
        selected_cls = "selected" if i == 0 else ""
        rows.append(
            f'<tr class="{selected_cls}" id="row-{i}" onclick="selectIncidentByIndex({i})">'
            f'<td>{severity_cell(inc["level"])}</td>'
            f'<td class="mono" style="font-weight:600;">{html.escape(str(inc["case_id"]))}</td>'
            f'<td class="mono" style="color:#8A97AB;">{html.escape(str(inc["time"]))}</td>'
            f'<td class="mono">{html.escape(str(inc["host_agent"]))}</td>'
            f'<td class="rule-cell">{html.escape(str(inc["rule_name"]))}</td>'
            f'<td><span class="badge {verdict_badge_class(v)}">{html.escape(v)}</span></td>'
            f'</tr>'
        )

    rows_str = "\n".join(rows) if rows else '<tr><td colspan="6" style="text-align:center;color:#8A97AB;padding:20px;">No incidents recorded</td></tr>'

    first = incidents[0] if incidents else {}
    first_v = first.get("verdict", "Suspicious / Review")
    first_fallback = "Enabled" if first.get("fallback_used") is True else ("None" if first.get("fallback_used") is False else "N/A")

    json_safe = json.dumps(incidents).replace("</", "<\\/")

    rendered = (
        HTML_TEMPLATE
        .replace("__TABLE_ROWS__", rows_str)
        .replace("__METRIC_TOTAL__", str(total))
        .replace("__METRIC_TP__", str(tp_count))
        .replace("__METRIC_FP__", str(fp_count))
        .replace("__METRIC_REVIEW__", str(review_count))
        .replace("__METRIC_CONTAINED__", str(contained_count))
        .replace("__INITIAL_ID__", html.escape(str(first.get("case_id", "NO INCIDENTS"))))
        .replace("__INITIAL_RULE__", html.escape(f"{first.get('rule_name', 'Security Alert')} [Severity Level {first.get('level', 0)}]"))
        .replace("__INITIAL_VERDICT_BADGE__", f'<span class="badge {verdict_badge_class(first_v)}">{html.escape(first_v)}</span>')
        .replace("__INITIAL_HOST__", html.escape(str(first.get("host_agent", "N/A"))))
        .replace("__INITIAL_SRC__", html.escape(str(first.get("source_ip", "N/A"))))
        .replace("__INITIAL_USER__", html.escape(str(first.get("user", "N/A"))))
        .replace("__INITIAL_CONTAINMENT__", html.escape(str(first.get("containment", "Not executed"))))
        .replace("__INITIAL_DETAILS__", html.escape(str(first.get("details", "No forensic notes."))))
        .replace("__INITIAL_PROVIDER__", html.escape(str(first.get("llm_provider", "unknown"))))
        .replace("__INITIAL_MODEL__", html.escape(str(first.get("llm_model", "unknown"))))
        .replace("__INITIAL_FALLBACK__", first_fallback)
        .replace("__JSON_DATA__", json_safe)
    )

    return HTMLResponse(content=rendered, headers={"Cache-Control": "no-store, no-cache, must-revalidate"})
