"""Compact incident triage dashboard with safe, readable investigation reports."""
import html
import json
from fastapi.responses import HTMLResponse
if __package__:
    from .grc_dashboard import GRC_STYLE, GRC_VIEW, GRC_SCRIPT
    from .casework.dashboard import STYLE as CASE_STYLE, VIEW as CASE_VIEW, SCRIPT as CASE_SCRIPT
else:
    from grc_dashboard import GRC_STYLE, GRC_VIEW, GRC_SCRIPT
    from casework.dashboard import STYLE as CASE_STYLE, VIEW as CASE_VIEW, SCRIPT as CASE_SCRIPT

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHAM AI · SOC &amp; GRC</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      color-scheme: dark;
      --bg: #070A10; --surface: #0D121C; --surface-2: #111B2A; --deep: #080D15;
      --border: #202C3E; --text: #E6EBF2; --text-2: #B4BFD0; --muted: #8A97AB;
      --cyan: #4CC9F0; --red: #FF7A87; --amber: #FFA94D; --yellow: #F5D547; --green: #3DDC97;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; scrollbar-width: thin; scrollbar-color: #34465F transparent; }
    [hidden] { display: none !important; }
    body { background: var(--bg); color: var(--text); font-family: 'IBM Plex Sans', system-ui, sans-serif; min-height: 100vh; line-height: 1.45; }
    .mono { font-family: 'IBM Plex Mono', monospace; font-variant-numeric: tabular-nums; }
    button { font-family: inherit; cursor: pointer; }
    button:focus-visible, input:focus-visible, [tabindex]:focus-visible { outline: 2px solid var(--cyan); outline-offset: -2px; }
    header { display: flex; gap: 12px; align-items: center; justify-content: space-between; padding: 10px 18px; border-bottom: 1px solid var(--border); background: #0A0F18; flex-shrink: 0; }
    .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
    .brand-title { font-weight: 600; font-size: 14px; letter-spacing: .07em; }
    .brand-sub { font-size: 11px; color: var(--muted); }
    .head-right { display: flex; gap: 12px; align-items: center; font-family: 'IBM Plex Mono', monospace; font-size: 11px; flex-shrink: 0; }
    .live { display: inline-flex; align-items: center; gap: 7px; border: 1px solid #1F5E48; color: var(--green); padding: 4px 9px; border-radius: 5px; white-space: nowrap; }
    .live i { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
    .clock { color: var(--muted); }
    .layout { padding: 12px 16px; display: flex; flex-direction: column; gap: 10px; width: 100%; min-height: 0; flex: 1; }
    .kpis { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px; flex-shrink: 0; }
    .kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 7px; padding: 10px 13px; position: relative; overflow: hidden; }
    .kpi::before { content: ''; position: absolute; inset: 12px auto 12px 0; width: 2px; background: var(--muted); }
    .kpi:nth-child(2)::before { background: var(--red); }
    .kpi:nth-child(3)::before { background: var(--yellow); }
    .kpi:nth-child(4)::before { background: var(--green); }
    .kpi:nth-child(5)::before { background: var(--cyan); }
    .kpi .l { font-size: 10px; letter-spacing: .055em; color: var(--muted); text-transform: uppercase; }
    .kpi .v { font-family: 'IBM Plex Mono', monospace; font-size: 26px; font-weight: 600; line-height: 1.2; margin-top: 4px; font-variant-numeric: tabular-nums; }
    .toolbar { display: flex; gap: 8px; align-items: center; background: var(--surface); border: 1px solid var(--border); border-radius: 7px; padding: 7px; flex-shrink: 0; }
    .search { display: flex; align-items: center; gap: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 0 10px; min-width: 160px; flex: 1; }
    .search svg { flex-shrink: 0; }
    .search input { background: transparent; border: 0; color: var(--text); font-size: 12px; height: 36px; width: 100%; min-width: 0; }
    .search input::placeholder { color: var(--muted); }
    .pills { display: flex; gap: 4px; }
    .pill, .sync, .report-toggle { min-height: 36px; padding: 0 12px; border-radius: 5px; border: 1px solid var(--border); background: #0A0F18; color: var(--text-2); font-size: 12px; white-space: nowrap; }
    .pill:hover, .sync:hover, .report-toggle:hover { background: var(--surface-2); color: var(--text); border-color: #3B506C; }
    .pill.active { border-color: #2F7891; background: #102A38; color: var(--cyan); font-weight: 600; }
    .sync { color: var(--text); font-weight: 600; }
    .workspace { display: grid; grid-template-columns: minmax(0, 1.16fr) minmax(0, 1fr); gap: 10px; min-height: 0; flex: 1; }
    .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 7px; min-width: 0; min-height: 0; overflow: hidden; }
    .feed { display: flex; flex-direction: column; }
    .panel-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 11px; color: var(--muted); flex-shrink: 0; }
    .panel-head > span:first-child { color: var(--text); font-weight: 600; }
    #visible-count { background: var(--surface-2); color: var(--cyan); border-radius: 4px; padding: 2px 6px; margin-left: 4px; font-variant-numeric: tabular-nums; }
    .scroll-x { overflow: auto; flex: 1; min-height: 0; overscroll-behavior: contain; }
    table { width: 100%; table-layout: fixed; border-collapse: collapse; font-size: 12px; }
    .col-severity { width: 76px; } .col-case { width: 164px; } .col-verdict { width: 112px; }
    th { position: sticky; top: 0; z-index: 1; background: #101824; text-align: left; color: var(--muted); font-size: 10px; letter-spacing: .05em; font-weight: 500; padding: 9px 10px; border-bottom: 1px solid var(--border); text-transform: uppercase; }
    td { padding: 9px 10px; border-bottom: 1px solid #192334; vertical-align: middle; overflow: hidden; }
    tbody tr { cursor: pointer; }
    tbody tr:hover { background: #101B2A; }
    tr.selected { background: var(--surface-2); box-shadow: inset 3px 0 0 var(--cyan); }
    .case-button { display: block; width: 100%; border: 0; background: transparent; color: var(--text); font-size: 11px; font-weight: 500; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 2px 0; }
    .cell-sub { display: block; margin-top: 3px; color: var(--muted); font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .rule-name { display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 1; overflow: hidden; color: var(--text-2); line-height: 1.4; }
    .sev { font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 500; white-space: nowrap; }
    .sev-crit { color: var(--red); } .sev-high { color: var(--amber); } .sev-med { color: var(--yellow); } .sev-low { color: var(--green); }
    .badge { display: inline-block; font-size: 10px; font-weight: 600; padding: 3px 7px; border-radius: 4px; text-transform: uppercase; border: 1px solid; line-height: 1.4; overflow-wrap: anywhere; }
    .badge-tp { color: var(--red); border-color: #66303A; background: #2A151D; }
    .badge-fp { color: var(--green); border-color: #245940; background: #10271F; }
    .badge-susp { color: var(--yellow); border-color: #62551E; background: #282312; }
    .inspector { padding: 12px; display: flex; flex-direction: column; gap: 10px; }
    .insp-head { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: start; gap: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
    .insp-id { font-family: 'IBM Plex Mono', monospace; font-size: 13px; font-weight: 600; overflow-wrap: anywhere; }
    .insp-rule { font-size: 12px; color: var(--text-2); margin-top: 4px; overflow-wrap: anywhere; }
    #insp-verdict-badge { max-width: 110px; }
    .grid2 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; flex-shrink: 0; }
    .art { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 8px; min-width: 0; }
    .art .al { font-size: 9px; letter-spacing: .055em; color: var(--muted); margin-bottom: 4px; text-transform: uppercase; }
    .art .av { font-family: 'IBM Plex Mono', monospace; font-size: 11px; overflow-wrap: anywhere; }
    .report { background: var(--deep); border: 1px solid var(--border); border-radius: 6px; display: flex; flex-direction: column; min-height: 120px; flex: 1; overflow: hidden; }
    .report-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 10px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
    .report-title { font-size: 10px; letter-spacing: .055em; color: var(--cyan); text-transform: uppercase; }
    .report-toggle { min-height: 28px; padding: 0 8px; font-size: 10px; }
    .report-text { font-size: 12px; line-height: 1.55; overflow: auto; overflow-wrap: anywhere; padding: 10px 12px; min-height: 0; flex: 1; overscroll-behavior: contain; }
    .report-text.raw { font-family: 'IBM Plex Mono', monospace; font-size: 11px; white-space: pre-wrap; }
    .report-text h3 { font-size: 12px; font-weight: 600; color: #DBEAF7; margin: 12px 0 5px; }
    .report-text h3:first-child { margin-top: 0; }
    .report-text p { margin: 4px 0; color: var(--text-2); }
    .report-text ul, .report-text ol { padding-left: 18px; margin: 4px 0 8px; color: var(--text-2); }
    .report-text li { padding-left: 2px; margin: 3px 0; }
    .report-text li::marker { color: var(--muted); }
    .report-text strong { color: var(--text); font-weight: 500; }
    .report-text code { font-family: 'IBM Plex Mono', monospace; font-size: .92em; color: #A5DCEC; }
    .report-text pre { padding: 9px; margin: 6px 0; border: 1px solid var(--border); border-radius: 4px; background: var(--bg); overflow-x: auto; white-space: pre-wrap; }
    .report-text hr { height: 1px; border: 0; background: var(--border); margin: 8px 0; }
    .foot { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 10px; font-size: 10px; color: var(--muted); flex-shrink: 0; overflow-wrap: anywhere; }
    .foot span span { color: var(--text-2); }
    .empty-state { padding: 28px 16px; text-align: center; color: var(--muted); font-size: 12px; }
    .empty-state strong { display: block; margin-bottom: 6px; color: var(--text-2); font-size: 14px; }
    @media (min-width: 1100px) and (min-height: 600px) {
      body { height: 100vh; height: 100dvh; display: flex; flex-direction: column; overflow: hidden; }
    }
    @media (max-width: 1199px) { .grid2 { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    @media (max-width: 1099px), (max-height: 599px) {
      .workspace { grid-template-columns: minmax(0, 1fr); }
      .scroll-x { max-height: 380px; }
      .report-text { max-height: 520px; }
      .grid2 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    }
    @media (max-width: 760px) {
      header { padding: 10px 12px; flex-wrap: wrap; }
      .head-right { gap: 8px; } .clock { display: none; }
      .layout { padding: 10px; gap: 8px; }
      .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; }
      .kpi { padding: 9px 10px; } .kpi .l { font-size: 9px; } .kpi .v { font-size: 23px; }
      .kpi:first-child { grid-column: span 2; }
      .toolbar { flex-wrap: wrap; gap: 6px; }
      .search { flex: 1 1 calc(100% - 90px); } .sync { order: 1; }
      .pills { order: 2; width: 100%; } .pill { flex: 1; padding: 0 7px; font-size: 11px; }
      .search input, .pill, .sync { min-height: 40px; }
      .workspace { gap: 8px; } .panel-head { padding: 9px 10px; }
      .col-severity { width: 66px; } .col-case { width: 142px; } .col-verdict { width: 98px; }
      td, th { padding: 8px; } .inspector { padding: 10px; }
      .grid2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 520px) {
      .brand-title { font-size: 12px; } .brand-sub { font-size: 10px; } .live { font-size: 9px; }
      .panel-head > span:last-child { font-size: 10px; }
      .col-severity, .severity-cell { display: none; }
      .col-case { width: 118px; } .col-verdict { width: 84px; }
      .case-button { font-size: 10px; } .cell-sub { font-size: 9px; }
      .rule-name { font-size: 11px; -webkit-line-clamp: 2; } .badge { font-size: 9px; padding: 3px 5px; }
      td, th { padding: 7px 6px; }
      .insp-head { gap: 6px; } .insp-id { font-size: 12px; }
    }
__GRC_STYLES__
__CASE_STYLES__
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#4CC9F0" stroke-width="1.8" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>
      <div>
        <div class="brand-title">AI-AGENT DASHBOARD</div>
        <div class="brand-sub">Evidence-led investigations · Human-led decisions</div>
      </div>
    </div>
    <div class="head-right">
      <span class="live"><i></i>STREAM ACTIVE</span>
      <span class="clock" id="clock-display">--:--:-- UTC</span>
    </div>
  </header>

  <nav class="mode-nav" role="tablist" aria-label="Dashboard workspace">
    <button class="mode-tab" id="mode-soc" role="tab" aria-controls="soc-view" aria-selected="true" onclick="location.hash='soc'">SOC incidents</button>
    <button class="mode-tab" id="mode-investigations" role="tab" aria-controls="investigations-view" aria-selected="false" tabindex="-1" onclick="location.hash='investigations/cases'">Investigations</button>
    <button class="mode-tab" id="mode-grc" role="tab" aria-controls="grc-view" aria-selected="false" tabindex="-1" onclick="location.hash='grc/evidence'">GRC workspace</button>
    <button class="soc-update" id="soc-update" hidden onclick="location.reload()">New SOC data · Refresh</button>
  </nav>
  <main class="layout" id="soc-view" role="tabpanel" aria-labelledby="mode-soc">
    <p class="soc-notice" id="soc-incident-notice" role="status" hidden></p>

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
        <button class="pill active" aria-pressed="true" data-filter="All" onclick="setFilter('All')">All</button>
        <button class="pill" aria-pressed="false" data-filter="Critical TP" onclick="setFilter('Critical TP')">Critical TP</button>
        <button class="pill" aria-pressed="false" data-filter="Suspicious / Review" onclick="setFilter('Suspicious / Review')">Needs review</button>
        <button class="pill" aria-pressed="false" data-filter="Benign/FP" onclick="setFilter('Benign/FP')">Benign / FP</button>
      </div>
      <button class="sync" onclick="location.reload()">Sync DB</button>
    </section>

    <section class="workspace">

      <div class="panel feed">
        <div class="panel-head">
          <span>Triage feed <span id="visible-count" aria-live="polite">__METRIC_TOTAL__</span></span>
          <span>Click a row to inspect</span>
        </div>
        <div class="scroll-x">
          <table aria-label="Security incidents">
            <colgroup><col class="col-severity"><col class="col-case"><col><col class="col-verdict"></colgroup>
            <thead>
              <tr><th class="severity-cell" scope="col">Level</th><th scope="col">Incident / time</th><th scope="col">Rule / host</th><th scope="col">Verdict</th></tr>
            </thead>
            <tbody id="incidents-tbody">
__TABLE_ROWS__
            </tbody>
          </table>
        </div>
        <div class="empty-state" id="no-results" hidden><strong>No matching incidents</strong>Try another search or filter.</div>
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
          <div class="report-head"><div class="report-title">AI Analyst Investigation Notes</div><button class="report-toggle" id="open-linked-case" onclick="if(allIncidents[selectedIndex])location.hash='investigations/incident/'+encodeURIComponent(allIncidents[selectedIndex].case_id)">Case &amp; evidence ↗</button><button class="report-toggle" id="report-toggle" onclick="toggleReportView()" aria-pressed="false">Raw report</button></div>
          <div class="report-text raw" id="insp-details" tabindex="0" role="region" aria-label="Investigation report">__INITIAL_DETAILS__</div>
        </div>

        <div class="foot">
          <span>Agent: <span id="insp-provider">__INITIAL_PROVIDER__</span> (<span id="insp-model">__INITIAL_MODEL__</span>)</span>
          <span>Fallback: <span id="insp-fallback">__INITIAL_FALLBACK__</span></span>
        </div>
      </div>
      <div class="panel empty-state" id="inspector-empty" hidden><strong>No incident selected</strong>Select an incident from the triage feed to read its report.</div>

    </section>
  </main>
__GRC_VIEW__
__CASE_VIEW__

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

    let rawReport = false;
    let selectedIndex = allIncidents.length ? 0 : -1;

    // Only create text nodes and a small set of formatting elements. Reports
    // contain untrusted alert/model text; never interpret their HTML or links.
    function appendReportInline(parent, text) {
      const pieces = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
      pieces.forEach(piece => {
        if (piece.startsWith('`') && piece.endsWith('`') && piece.length > 2) {
          const code = document.createElement('code');
          code.textContent = piece.slice(1, -1);
          parent.appendChild(code);
        } else if (piece.startsWith('**') && piece.endsWith('**') && piece.length > 4) {
          const strong = document.createElement('strong');
          strong.textContent = piece.slice(2, -2);
          parent.appendChild(strong);
        } else {
          parent.appendChild(document.createTextNode(piece));
        }
      });
    }

    function renderReport(text) {
      const target = document.getElementById('insp-details');
      const source = String(text || 'No investigation notes recorded.');
      target.replaceChildren();
      target.classList.toggle('raw', rawReport);
      document.getElementById('report-toggle').textContent = rawReport ? 'Formatted report' : 'Raw report';
      document.getElementById('report-toggle').setAttribute('aria-pressed', String(rawReport));
      if (rawReport) {
        target.textContent = source;
      } else {
        let list = null;
        let code = null;
        for (const line of source.replace(/\r\n?/g, '\n').split('\n')) {
          if (line.trim().startsWith('```')) {
            list = null;
            if (code) { code = null; } else {
              const pre = document.createElement('pre');
              code = document.createElement('code');
              pre.appendChild(code);
              target.appendChild(pre);
            }
            continue;
          }
          if (code) { code.textContent += line + '\n'; continue; }
          const trimmed = line.trim();
          if (!trimmed) { list = null; continue; }
          const heading = trimmed.match(/^#{1,6}\s+(.+)$/);
          const bullet = trimmed.match(/^(?:[-*+]\s+|\d+[.)]\s+)(.+)$/);
          if (bullet) {
            const ordered = /^\d/.test(trimmed);
            const tag = ordered ? 'OL' : 'UL';
            if (!list || list.tagName !== tag) {
              list = document.createElement(tag.toLowerCase());
              if (ordered) list.start = parseInt(trimmed, 10);
              target.appendChild(list);
            }
            const li = document.createElement('li');
            appendReportInline(li, bullet[1]);
            list.appendChild(li);
            continue;
          }
          list = null;
          const node = document.createElement(heading ? 'h3' : (/^([-*_])\1{2,}$/.test(trimmed) ? 'hr' : 'p'));
          if (node.tagName !== 'HR') appendReportInline(node, heading ? heading[1] : trimmed);
          target.appendChild(node);
        }
      }
      target.scrollTop = 0;
    }

    function toggleReportView() {
      rawReport = !rawReport;
      renderReport(allIncidents[selectedIndex]?.details);
    }

    function selectIncidentByIndex(idx) {
      const item = allIncidents[idx];
      if (!item) return;
      selectedIndex = idx;
      document.getElementById("inspector-card").hidden = false;
      document.getElementById("inspector-empty").hidden = true;
      document.querySelectorAll(".case-button").forEach(button => button.setAttribute("aria-pressed", "false"));
      document.querySelector("#row-" + idx + " .case-button").setAttribute("aria-pressed", "true");

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
      renderReport(item.details);
      document.getElementById('insp-provider').innerText = item.llm_provider || "unknown";
      document.getElementById('insp-model').innerText = item.llm_model || "unknown";
      const fb = item.fallback_used === true ? "Enabled" : (item.fallback_used === false ? "None" : "N/A");
      document.getElementById('insp-fallback').innerText = fb;
    }

    function setFilter(filter) {
      currentFilter = filter;
      document.querySelectorAll('.pill').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
        btn.setAttribute("aria-pressed", String(btn.dataset.filter === filter));
      });
      applyFilters();
    }

    function handleSearch() {
      searchQuery = document.getElementById('search-input').value.toLowerCase().trim();
      applyFilters();
    }

    function applyFilters() {
      let count = 0;
      const visible = [];
      allIncidents.forEach((inc, idx) => {
        const row = document.getElementById('row-' + idx);
        if (!row) return;
        const matchesFilter = (currentFilter === "All") || (inc.verdict === currentFilter) ||
          (currentFilter === "Critical TP" && inc.verdict.includes("Critical")) ||
          (currentFilter === "Benign/FP" && inc.verdict.includes("Benign"));
        const blob = (inc.case_id + " " + inc.host_agent + " " + inc.source_ip + " " + inc.rule_name + " " + inc.user).toLowerCase();
        const matchesSearch = !searchQuery || blob.includes(searchQuery);
        if (matchesFilter && matchesSearch) { row.style.display = ""; count++; visible.push(idx); }
        else { row.style.display = "none"; }
      });
      document.getElementById('visible-count').innerText = count;
      document.getElementById('no-results').hidden = count > 0 || allIncidents.length === 0;
      document.getElementById('inspector-card').hidden = count === 0;
      document.getElementById('inspector-empty').hidden = count > 0;
      if (count && !visible.includes(selectedIndex)) selectIncidentByIndex(visible[0]);
    }

    function connectWS() {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(proto + '//' + window.location.host + '/ws');
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "NEW_ALERT") {
          window.dispatchEvent(new Event('soc-new-alert'));
          if (document.getElementById('soc-view').hidden) document.getElementById('soc-update').hidden=false;
          else location.reload();
        }
      };
      ws.onclose = () => setTimeout(connectWS, 3000);
    }
__GRC_SCRIPT__
__CASE_SCRIPT__
    function routeWorkspace() {
      const hash=location.hash.slice(1), mode=hash.startsWith('investigations')?'investigations':hash==='grc'||hash.startsWith('grc/')?'grc':'soc';
      ['soc','investigations','grc'].forEach(key=>{const active=key===mode,node=document.getElementById('mode-'+key);document.getElementById(key+'-view').hidden=!active;node.setAttribute('aria-selected',String(active));node.tabIndex=active?0:-1;});
      if(mode==='investigations'){window.showInvestigationRoute();return;}
      if(mode==='grc'){const [section,query='']=hash.replace(/^grc\/?/,'').split('?');window.showGrcRoute(section||'evidence',(new URLSearchParams(query).get('record')||'').slice(0,128));return;}
      const notice=document.getElementById('soc-incident-notice');notice.hidden=true;
      if(hash.startsWith('soc/incident/')){
        let id;try{id=decodeURIComponent(hash.slice(13));}catch{return;}
        document.getElementById('search-input').value=id;searchQuery=id.toLowerCase();setFilter('All');
        const index=allIncidents.findIndex(x=>x.case_id===id);
        if(index>=0){selectIncidentByIndex(index);document.getElementById('insp-details').focus();}
        else{notice.textContent='This incident is no longer available in SOC. Related evidence may still be retained in GRC.';notice.hidden=false;}
      }
    }
    window.addEventListener('hashchange',routeWorkspace);
    document.querySelector('.mode-nav').addEventListener('keydown',event=>{
      if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)||!document.activeElement.classList.contains('mode-tab'))return;
      event.preventDefault();const tabs=[...document.querySelectorAll('.mode-tab')],index=tabs.indexOf(document.activeElement),target=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[target].focus();tabs[target].click();
    });
    renderReport(allIncidents[0]?.details);
    applyFilters();
    routeWorkspace();
    connectWS();
  </script>
</body>
</html>"""

HTML_TEMPLATE = HTML_TEMPLATE.replace('__GRC_STYLES__', GRC_STYLE).replace('__GRC_VIEW__', GRC_VIEW).replace('__GRC_SCRIPT__', GRC_SCRIPT)
HTML_TEMPLATE = HTML_TEMPLATE.replace('__CASE_STYLES__', CASE_STYLE).replace('__CASE_VIEW__', CASE_VIEW).replace('__CASE_SCRIPT__', CASE_SCRIPT)

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
        case_id = html.escape(str(inc["case_id"]), quote=True)
        rule = html.escape(str(inc["rule_name"]), quote=True)
        host = html.escape(str(inc["host_agent"]), quote=True)
        rows.append(
            f'<tr class="{selected_cls}" id="row-{i}" onclick="selectIncidentByIndex({i})">'
            f'<td class="severity-cell">{severity_cell(inc["level"])}</td>'
            f'<td><button class="case-button mono" title="{case_id}" aria-label="Inspect {case_id}" '
            f'aria-pressed="{str(i == 0).lower()}">{case_id}</button>'
            f'<span class="cell-sub mono">{html.escape(str(inc["time"]))}</span></td>'
            f'<td><span class="rule-name" title="{rule}">{rule}</span>'
            f'<span class="cell-sub mono" title="Host: {host}">{host}</span></td>'
            f'<td><span class="badge {verdict_badge_class(v)}">{html.escape(v)}</span></td>'
            f'</tr>'
        )

    rows_str = "\n".join(rows) if rows else '<tr><td colspan="4" class="empty-state">No incidents recorded</td></tr>'

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
