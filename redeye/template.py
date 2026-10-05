"""The HTML report template, kept out of report.py for readability.

The design is a "surveillance console": a dark operator's monitor wall where
each captured host is a channel. Amber is reserved for high-interest hosts;
status colors stay semantic. Progressive disclosure is the rule -- a card shows
the essentials, and clicking it slides in a panel with the full recon detail
(TLS, security headers, redirect chain, raw headers).
"""

from __future__ import annotations

REPORT_TEMPLATE = r"""<!doctype html>
<html lang="en" data-view="grid">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>redeye · recon report</title>
<style>
  /* Direction: a night-shift surveillance console. Dark ground with amber as
     the single "needs attention" accent is grounded in the subject (operator
     monitor walls, cockpit warning amber), not a random acid accent, and the
     full semantic status palette (green/cyan/amber/red) lives alongside it.
     avoid-ai-design-ignore: SD2 */
  :root {
    --bg:        #0b1019;
    --bg-grid:   #0e141f;
    --panel:     #141c2a;
    --panel-2:   #1a2434;
    --line:      #243044;
    --line-soft: #1b2434;
    --ink:       #e4e9f1;
    --ink-dim:   #8a97ab;
    --ink-faint: #566072;
    --amber:     #f5a623;
    --amber-dim: #7a5a1e;
    --ok:        #45d67f;
    --info:      #42c4d4;
    --warn:      #e0a93b;
    --bad:       #f05d5d;
    /* self-contained: only fonts already on the machine, no web fetch
       (redeye reports must work fully offline). avoid-ai-design-ignore: T7 */
    --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body {
    background:
      linear-gradient(var(--bg-grid) 1px, transparent 1px) 0 0 / 100% 34px,
      var(--bg);
    color: var(--ink);
    font: 14px/1.5 var(--sans);
    -webkit-font-smoothing: antialiased;
  }
  a { color: inherit; }

  /* ---- console bar ---- */
  .console {
    position: sticky; top: 0; z-index: 30;
    background: color-mix(in srgb, var(--panel) 92%, transparent);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--line);
    padding: 12px 20px;
    display: flex; align-items: center; gap: 20px; flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 600;
           letter-spacing: .5px; }
  .brand .eye {
    width: 13px; height: 13px; border-radius: 50%;
    background: var(--bad); position: relative;
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--bad) 22%, transparent);
    animation: pulse 2.6s ease-in-out infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.45} }
  @media (prefers-reduced-motion: reduce) { .brand .eye { animation: none; } }
  .brand b { font-family: var(--mono); }

  .counts { display: flex; gap: 18px; align-items: center;
            font-family: var(--mono); font-size: 12px; color: var(--ink-dim); }
  .counts .n { color: var(--ink); font-size: 15px; }
  .counts .hot .n { color: var(--amber); }

  /* status distribution meter */
  .meter { display: flex; height: 8px; min-width: 160px; flex: 0 1 240px;
           border-radius: 2px; overflow: hidden; border: 1px solid var(--line); }
  .meter > span { display: block; }
  .seg-green  { background: var(--ok); }
  .seg-cyan   { background: var(--info); }
  .seg-yellow { background: var(--warn); }
  .seg-red    { background: var(--bad); }
  .seg-grey   { background: var(--ink-faint); }

  .spacer { flex: 1; }

  .filter {
    background: var(--bg); border: 1px solid var(--line); color: var(--ink);
    font: 13px var(--mono); padding: 7px 11px 7px 30px; border-radius: 7px;
    min-width: 230px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%238a97ab' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m21 21-4.3-4.3'/%3E%3C/svg%3E");
    background-repeat: no-repeat; background-position: 10px center;
  }
  .filter:focus { outline: none; border-color: var(--amber);
                  box-shadow: 0 0 0 2px color-mix(in srgb, var(--amber) 20%, transparent); }

  .toggle { display: flex; border: 1px solid var(--line); border-radius: 7px;
            overflow: hidden; }
  .toggle button {
    background: var(--bg); color: var(--ink-dim); border: 0; cursor: pointer;
    padding: 7px 10px; font: 12px var(--mono); display: flex; align-items: center;
    gap: 5px;
  }
  .toggle button + button { border-left: 1px solid var(--line); }
  .toggle button[aria-pressed="true"] { background: var(--panel-2); color: var(--amber); }
  .toggle svg { width: 14px; height: 14px; }

  /* ---- sections ---- */
  main { padding: 22px 20px 80px; max-width: 1600px; margin: 0 auto; }
  section { margin-bottom: 30px; }
  .sec-head { display: flex; align-items: center; gap: 10px; margin: 0 0 14px;
              font-family: var(--mono); font-size: 12px; letter-spacing: 1.5px;
              text-transform: uppercase; color: var(--ink-dim); }
  .sec-head::before { content: ""; width: 7px; height: 7px; border-radius: 1px;
                      background: var(--ink-faint); }
  .sec-head.hot { color: var(--amber); }
  .sec-head.hot::before { background: var(--amber);
                          box-shadow: 0 0 10px var(--amber); }
  .sec-head .count { color: var(--ink-faint); }
  .sec-head .rule { flex: 1; height: 1px; background: var(--line-soft); }

  /* ---- grid view ---- */
  .grid { display: grid; gap: 14px;
          grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); }

  .card {
    position: relative; background: var(--panel);
    border: 1px solid var(--line); border-radius: 10px; overflow: hidden;
    cursor: pointer; display: flex; flex-direction: column;
    transition: border-color .15s, transform .1s;
  }
  .card:hover { border-color: var(--ink-faint); transform: translateY(-2px); }
  .card:focus-visible { outline: 2px solid var(--amber); outline-offset: 2px; }
  /* status spine down the left edge */
  .card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0;
                  width: 3px; z-index: 2; }
  .card.c-green::before  { background: var(--ok); }
  .card.c-cyan::before   { background: var(--info); }
  .card.c-yellow::before { background: var(--warn); }
  .card.c-red::before    { background: var(--bad); }
  .card.c-grey::before   { background: var(--ink-faint); }
  .card.hot { border-color: var(--amber-dim); }
  /* reticle bracket, top-right, only on hot cards */
  .card.hot .reticle { position: absolute; top: 8px; right: 8px; z-index: 3;
                       width: 16px; height: 16px; pointer-events: none; }
  .card.hot .reticle::before, .card.hot .reticle::after {
    content: ""; position: absolute; top: 0; right: 0; }
  .card.hot .reticle::before { width: 16px; height: 2px; background: var(--amber); }
  .card.hot .reticle::after  { width: 2px; height: 16px; background: var(--amber);
                               right: 0; }

  .shot { aspect-ratio: 16/10; background: #060a11; overflow: hidden;
          border-bottom: 1px solid var(--line-soft); position: relative; }
  .shot img { width: 100%; height: 100%; object-fit: cover; object-position: top;
              display: block; filter: saturate(.92); }
  .shot .noshot { display: flex; align-items: center; justify-content: center;
                  height: 100%; color: var(--ink-faint); font: 11px var(--mono);
                  letter-spacing: 1px; text-transform: uppercase; }
  .shot .status-chip {
    position: absolute; left: 8px; bottom: 8px; z-index: 2;
    font: 600 11px var(--mono); padding: 2px 7px; border-radius: 4px;
    background: color-mix(in srgb, var(--bg) 78%, transparent);
    border: 1px solid var(--line);
  }
  .chip-green  { color: var(--ok); }
  .chip-cyan   { color: var(--info); }
  .chip-yellow { color: var(--warn); }
  .chip-red    { color: var(--bad); }
  .chip-grey   { color: var(--ink-dim); }

  .meta { padding: 10px 12px 12px; display: flex; flex-direction: column; gap: 7px;
          min-width: 0; }
  .host { font: 13px var(--mono); color: var(--ink); word-break: break-all;
          line-height: 1.35; }
  .ptitle { font-size: 12px; color: var(--ink-dim); white-space: nowrap;
            overflow: hidden; text-overflow: ellipsis; }
  .tags { display: flex; gap: 5px; flex-wrap: wrap; }
  .tag { font: 11px var(--mono); padding: 1px 7px; border-radius: 4px;
         background: var(--panel-2); color: var(--ink-dim);
         border: 1px solid var(--line-soft); }
  .tag.hot { background: color-mix(in srgb, var(--amber) 16%, transparent);
             color: var(--amber); border-color: var(--amber-dim); }
  .microrow { display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
              font: 11px var(--mono); color: var(--ink-faint); }
  .microrow .warn-sec { color: var(--warn); }

  /* ---- list view ---- */
  html[data-view="list"] .grid { display: block; }
  html[data-view="list"] .card { flex-direction: row; align-items: stretch;
    border-radius: 7px; margin-bottom: 6px; transform: none; }
  html[data-view="list"] .card:hover { transform: none; }
  html[data-view="list"] .shot { aspect-ratio: auto; width: 120px; flex: none;
    border-bottom: 0; border-right: 1px solid var(--line-soft); }
  html[data-view="list"] .shot .status-chip { display: none; }
  html[data-view="list"] .card.hot .reticle { display: none; }
  html[data-view="list"] .meta { flex-direction: row; align-items: center;
    gap: 16px; width: 100%; padding: 8px 14px; }
  html[data-view="list"] .list-status { font: 600 13px var(--mono); width: 56px;
    flex: none; }
  html[data-view="list"] .host { flex: 1 1 260px; }
  html[data-view="list"] .ptitle { flex: 1 1 180px; }
  html[data-view="list"] .tags { flex: 0 1 auto; }
  html[data-view="list"] .microrow { margin-left: auto; }
  .list-status { display: none; }
  html[data-view="list"] .list-status { display: block; }
  html[data-view="list"] .list-status.s-green  { color: var(--ok); }
  html[data-view="list"] .list-status.s-cyan   { color: var(--info); }
  html[data-view="list"] .list-status.s-yellow { color: var(--warn); }
  html[data-view="list"] .list-status.s-red    { color: var(--bad); }
  html[data-view="list"] .list-status.s-grey   { color: var(--ink-dim); }

  /* ---- detail panel ---- */
  .scrim { position: fixed; inset: 0; background: rgba(4,8,14,.6);
           backdrop-filter: blur(2px); z-index: 40; opacity: 0;
           pointer-events: none; transition: opacity .18s; }
  .scrim.open { opacity: 1; pointer-events: auto; }
  .detail {
    position: fixed; top: 0; right: 0; bottom: 0; width: min(560px, 92vw);
    background: var(--panel); border-left: 1px solid var(--line); z-index: 50;
    transform: translateX(100%); transition: transform .22s cubic-bezier(.4,0,.2,1);
    display: flex; flex-direction: column;
  }
  .detail.open { transform: translateX(0); }
  .detail-head { padding: 14px 18px; border-bottom: 1px solid var(--line);
                 display: flex; align-items: flex-start; gap: 12px; }
  .detail-head .d-host { font: 14px var(--mono); word-break: break-all; flex: 1; }
  .detail-close { background: var(--bg); border: 1px solid var(--line);
                  color: var(--ink-dim); border-radius: 6px; width: 30px;
                  height: 30px; cursor: pointer; font-size: 16px; flex: none; }
  .detail-close:hover { color: var(--ink); border-color: var(--ink-faint); }
  .detail-body { overflow-y: auto; padding: 0 0 30px; }
  .detail-shot { width: 100%; display: block; border-bottom: 1px solid var(--line); }
  .dsec { padding: 14px 18px; border-bottom: 1px solid var(--line-soft); }
  .dsec h4 { margin: 0 0 10px; font: 11px var(--mono); letter-spacing: 1.2px;
             text-transform: uppercase; color: var(--ink-dim); }
  .kv { display: grid; grid-template-columns: 130px 1fr; gap: 4px 12px;
        font: 12px var(--mono); }
  .kv dt { color: var(--ink-faint); }
  .kv dd { margin: 0; color: var(--ink); word-break: break-all; }
  .sec-grid { display: flex; flex-direction: column; gap: 5px; font: 12px var(--mono); }
  .sec-row { display: flex; gap: 8px; align-items: baseline; }
  .sec-row .nm { color: var(--ink-dim); min-width: 180px; }
  .sec-ok  { color: var(--ok); }
  .sec-miss { color: var(--bad); }
  .redir { font: 12px var(--mono); color: var(--ink-dim); }
  .redir .hop { padding: 3px 0; }
  .redir .arrow { color: var(--ink-faint); }
  .rawh { font: 11px var(--mono); color: var(--ink-dim); white-space: pre-wrap;
          word-break: break-all; max-height: 240px; overflow-y: auto;
          background: var(--bg); border: 1px solid var(--line-soft);
          border-radius: 6px; padding: 10px; }
  .open-link { display: inline-flex; align-items: center; gap: 6px;
               font: 12px var(--mono); color: var(--amber); text-decoration: none;
               border: 1px solid var(--amber-dim); border-radius: 6px;
               padding: 6px 11px; }
  .open-link:hover { background: color-mix(in srgb, var(--amber) 12%, transparent); }

  .empty { color: var(--ink-faint); text-align: center; padding: 50px;
           font: 13px var(--mono); }
  footer { color: var(--ink-faint); font: 11px var(--mono); padding: 16px 20px;
           border-top: 1px solid var(--line-soft); text-align: center; }
  @media (max-width: 640px) {
    .counts { display: none; }
  }
</style>
</head>
<body>
<header class="console">
  <div class="brand"><span class="eye"></span> red<b>eye</b></div>
  <div class="counts">
    <span><span class="n">{{ total }}</span> hosts</span>
    <span><span class="n">{{ ok_count }}</span> up</span>
    <span class="hot"><span class="n">{{ high_count }}</span> flagged</span>
  </div>
  {% if distribution %}
  <div class="meter" title="status distribution">
    {% for d in distribution %}
    <span class="seg-{{ d.color }}" style="flex:{{ d.count }}"
          title="{{ d.label }}: {{ d.count }}"></span>
    {% endfor %}
  </div>
  {% endif %}
  <div class="spacer"></div>
  <input id="filter" class="filter" type="search" autocomplete="off"
         placeholder="filter hosts, titles, tags…" aria-label="filter">
  <div class="toggle" role="group" aria-label="view">
    <button id="view-grid" aria-pressed="true" title="grid view">
      <svg viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/></svg>
      grid
    </button>
    <button id="view-list" aria-pressed="false" title="list view">
      <svg viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="4" width="18" height="3" rx="1"/><rect x="3" y="10.5" width="18" height="3" rx="1"/><rect x="3" y="17" width="18" height="3" rx="1"/></svg>
      list
    </button>
  </div>
</header>

<main id="report">
  {% for group in groups %}
  <section data-group>
    <h2 class="sec-head {% if group.hot %}hot{% endif %}">
      {{ group.title }} <span class="count">{{ group.cards|length }}</span>
      <span class="rule"></span>
    </h2>
    <div class="grid">
      {% for c in group.cards %}
      <article class="card c-{{ c.color }} {% if c.high_interest %}hot{% endif %}"
               tabindex="0" role="button"
               data-search="{{ c.search }}"
               data-card='{{ c|tojson|forceescape }}'>
        {% if c.high_interest %}<span class="reticle"></span>{% endif %}
        <span class="list-status s-{{ c.color }}">{{ c.status_label if c.status_label|length < 7 else '!' }}</span>
        <div class="shot">
          {% if c.screenshot %}
          <img loading="lazy" src="{{ c.screenshot }}" alt="screenshot of {{ c.host }}">
          {% else %}<div class="noshot">no signal</div>{% endif %}
          <span class="status-chip chip-{{ c.color }}">{{ c.status_label }}</span>
        </div>
        <div class="meta">
          <div class="host">{{ c.host }}</div>
          {% if c.title %}<div class="ptitle">{{ c.title }}</div>{% endif %}
          {% if c.tech %}
          <div class="tags">
            {% for t in c.tech %}<span class="tag {% if c.high_interest %}hot{% endif %}">{{ t }}</span>{% endfor %}
          </div>
          {% endif %}
          <div class="microrow">
            {% if c.elapsed_ms is not none %}<span>{{ c.elapsed_ms }}ms</span>{% endif %}
            {% if c.server %}<span>{{ c.server }}</span>{% endif %}
            {% if c.missing_security %}<span class="warn-sec">▲ {{ c.missing_security|length }} sec hdr</span>{% endif %}
          </div>
        </div>
      </article>
      {% endfor %}
    </div>
  </section>
  {% endfor %}
  <div class="empty" id="no-results" hidden>no hosts match your filter</div>
</main>

<footer>redeye · {{ generated }} · only scan targets you are authorized to test</footer>

<div class="scrim" id="scrim"></div>
<aside class="detail" id="detail" aria-hidden="true">
  <div class="detail-head">
    <div class="d-host" id="d-host"></div>
    <button class="detail-close" id="d-close" aria-label="close">✕</button>
  </div>
  <div class="detail-body" id="d-body"></div>
</aside>

<script>
(function () {
  "use strict";
  var root = document.documentElement;

  // ---- grid / list toggle (remembers choice per browser) ----
  var gridBtn = document.getElementById("view-grid");
  var listBtn = document.getElementById("view-list");
  function setView(v) {
    root.setAttribute("data-view", v);
    gridBtn.setAttribute("aria-pressed", String(v === "grid"));
    listBtn.setAttribute("aria-pressed", String(v === "list"));
    try { localStorage.setItem("redeye-view", v); } catch (e) {}
  }
  try { var saved = localStorage.getItem("redeye-view"); if (saved) setView(saved); } catch (e) {}
  gridBtn.addEventListener("click", function () { setView("grid"); });
  listBtn.addEventListener("click", function () { setView("list"); });

  // ---- filter ----
  var input = document.getElementById("filter");
  var cards = Array.prototype.slice.call(document.querySelectorAll(".card"));
  var sections = Array.prototype.slice.call(document.querySelectorAll("[data-group]"));
  var noResults = document.getElementById("no-results");
  function applyFilter() {
    var q = input.value.trim().toLowerCase();
    var any = false;
    cards.forEach(function (card) {
      var hit = !q || card.dataset.search.indexOf(q) !== -1;
      card.hidden = !hit;
      if (hit) any = true;
    });
    sections.forEach(function (s) {
      var visible = s.querySelectorAll(".card:not([hidden])").length;
      s.hidden = visible === 0;
    });
    noResults.hidden = any;
  }
  input.addEventListener("input", applyFilter);

  // ---- detail panel (progressive disclosure) ----
  var scrim = document.getElementById("scrim");
  var detail = document.getElementById("detail");
  var dHost = document.getElementById("d-host");
  var dBody = document.getElementById("d-body");

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  var SEC_NAMES = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy"
  };

  function buildDetail(c) {
    var h = "";
    if (c.screenshot) {
      h += '<img class="detail-shot" src="' + esc(c.screenshot) + '" alt="">';
    }

    // overview
    h += '<div class="dsec"><dl class="kv">';
    h += '<dt>status</dt><dd>' + esc(c.status_label) + '</dd>';
    if (c.final_url && c.final_url !== c.url) {
      h += '<dt>requested</dt><dd>' + esc(c.url) + '</dd>';
      h += '<dt>final url</dt><dd>' + esc(c.final_url) + '</dd>';
    } else {
      h += '<dt>url</dt><dd>' + esc(c.url) + '</dd>';
    }
    if (c.ip) h += '<dt>ip</dt><dd>' + esc(c.ip) + '</dd>';
    if (c.server) h += '<dt>server</dt><dd>' + esc(c.server) + '</dd>';
    if (c.content_type) h += '<dt>content-type</dt><dd>' + esc(c.content_type) + '</dd>';
    if (c.elapsed_ms != null) h += '<dt>response time</dt><dd>' + esc(c.elapsed_ms) + ' ms</dd>';
    if (c.title) h += '<dt>title</dt><dd>' + esc(c.title) + '</dd>';
    if (c.favicon_hash) h += '<dt>favicon</dt><dd>' + esc(c.favicon_hash) + '</dd>';
    if (c.error) h += '<dt>note</dt><dd style="color:var(--bad)">' + esc(c.error) + '</dd>';
    h += '</dl>';
    h += '<div style="margin-top:12px"><a class="open-link" target="_blank" rel="noopener" href="'
       + esc(c.final_url || c.url) + '">open in browser ↗</a></div></div>';

    // tech
    if (c.tech && c.tech.length) {
      h += '<div class="dsec"><h4>fingerprint</h4><div class="tags">';
      c.tech.forEach(function (t) {
        h += '<span class="tag' + (c.high_interest ? ' hot' : '') + '">' + esc(t) + '</span>';
      });
      h += '</div></div>';
    }

    // TLS
    if (c.tls && Object.keys(c.tls).length) {
      h += '<div class="dsec"><h4>tls certificate</h4><dl class="kv">';
      if (c.tls.subject) h += '<dt>subject</dt><dd>' + esc(c.tls.subject) + '</dd>';
      if (c.tls.issuer) h += '<dt>issuer</dt><dd>' + esc(c.tls.issuer) + '</dd>';
      if (c.tls.protocol) h += '<dt>protocol</dt><dd>' + esc(c.tls.protocol) + '</dd>';
      if (c.tls.valid_from) h += '<dt>valid from</dt><dd>' + esc(c.tls.valid_from) + '</dd>';
      if (c.tls.valid_to) h += '<dt>valid to</dt><dd>' + esc(c.tls.valid_to) + '</dd>';
      if (c.tls.self_signed) h += '<dt>note</dt><dd style="color:var(--warn)">self-signed</dd>';
      h += '</dl></div>';
    }

    // security headers
    if (c.security_headers && Object.keys(c.security_headers).length) {
      h += '<div class="dsec"><h4>security headers</h4><div class="sec-grid">';
      Object.keys(SEC_NAMES).forEach(function (k) {
        var v = c.security_headers[k];
        if (v === undefined) return;
        var present = v !== "missing";
        h += '<div class="sec-row"><span class="nm">' + esc(SEC_NAMES[k]) + '</span>'
          + (present
              ? '<span class="sec-ok">✓ ' + esc(v) + '</span>'
              : '<span class="sec-miss">✗ missing</span>')
          + '</div>';
      });
      h += '</div></div>';
    }

    // redirect chain
    if (c.redirects && c.redirects.length) {
      h += '<div class="dsec"><h4>redirect chain</h4><div class="redir">';
      c.redirects.forEach(function (r) {
        h += '<div class="hop"><span class="arrow">' + esc(r.status) + ' →</span> ' + esc(r.url) + '</div>';
      });
      h += '<div class="hop"><span class="arrow">200 ●</span> ' + esc(c.final_url || c.url) + '</div>';
      h += '</div></div>';
    }

    // raw headers
    if (c.headers && Object.keys(c.headers).length) {
      var raw = Object.keys(c.headers).map(function (k) {
        return k + ": " + c.headers[k];
      }).join("\n");
      h += '<div class="dsec"><h4>response headers</h4><div class="rawh">' + esc(raw) + '</div></div>';
    }

    return h;
  }

  function openDetail(card) {
    var c;
    try { c = JSON.parse(card.dataset.card); } catch (e) { return; }
    dHost.textContent = c.host;
    dBody.innerHTML = buildDetail(c);
    dBody.scrollTop = 0;
    scrim.classList.add("open");
    detail.classList.add("open");
    detail.setAttribute("aria-hidden", "false");
  }
  function closeDetail() {
    scrim.classList.remove("open");
    detail.classList.remove("open");
    detail.setAttribute("aria-hidden", "true");
  }
  cards.forEach(function (card) {
    card.addEventListener("click", function () { openDetail(card); });
    card.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDetail(card); }
    });
  });
  scrim.addEventListener("click", closeDetail);
  document.getElementById("d-close").addEventListener("click", closeDetail);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeDetail();
  });
})();
</script>
</body>
</html>
"""
