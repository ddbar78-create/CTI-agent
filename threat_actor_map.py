"""
Hotaktörskarta — var slår de olika ransomware-grupperna till?

Bygger en interaktiv sektion av redan insamlade offer (tabellen ransomware_victims,
dvs. ransomware.live och RansomLook):

  - Aktörslista (sorterbar på totalt eller nordiska offer, sökbar)
  - Världskarta med bubblor per land för vald aktör (eller alla), nordiska länder
    markerade, zoom/panorering och förvalda vyer Världen/Europa/Norden
  - Aktörsprofil: nyckeltal, vanligaste branscher och länder, senaste offer
  - Värmekarta aktör × bransch för de mest aktiva grupperna
  - Tidsfilter (30 dagar / 90 dagar / 1 år / allt), räknas om direkt i webbläsaren

Ingen LLM och inga nycklar. Kartlagret (D3 + world-atlas) laddas från CDN, men
lista, profil och värmekarta fungerar även om kartan inte skulle ladda.
Observera att kartan visar var OFFREN finns, inte var aktören sitter.
"""

import html
import json
import sqlite3

from storage import DB_PATH

MAX_ROWS = 4000

ACTOR_MAP_CSS = """
  .tam-hero { display: grid; grid-template-columns: 190px minmax(0, 1fr) 190px; gap: 0; background: #04070d; border: 1px solid #12305a; border-radius: 8px; overflow: hidden; box-shadow: 0 0 24px rgba(30,120,255,0.12); }
  @media (max-width: 980px) { .tam-hero { grid-template-columns: 1fr; } .tam-side { display: none; } }
  .tam-side { padding: 0.5rem 0.6rem; font-size: 0.74rem; color: #9fc4ff; background: linear-gradient(#071327, #04070d); }
  .tam-side h4 { margin: 0 0 0.4rem; font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase; color: #5fb0ff; border-bottom: 1px solid #12305a; padding-bottom: 0.3rem; }
  .tam-side div.r { display: grid; grid-template-columns: 2rem 1fr; gap: 0.3rem; padding: 0.12rem 0; align-items: center; }
  .tam-side .r b { font-family: var(--mono, monospace); text-align: right; color: #fff; font-weight: 500; }
  .tam-side .r span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .tam-side .r.nordic span, .tam-side .r.nordic b { color: #ff5a5a; }
  .tam-stage { position: relative; background: radial-gradient(ellipse at 50% 40%, #0a1a33 0%, #04070d 70%); }
  .tam-stage canvas { position: absolute; left: 0; top: 0; width: 100%; height: 100%; pointer-events: none; }
  .tam-stage svg { cursor: grab; width: 100%; height: auto; display: block; }
  .tam-tag { position: absolute; left: 0.7rem; top: 0.5rem; font-size: 0.7rem; letter-spacing: 0.14em; color: #5fb0ff; text-transform: uppercase; pointer-events: none; z-index: 2; }
  .tam-tag b { color: #fff; font-size: 0.95rem; letter-spacing: 0.1em; display: block; }
  .tam-live { position: absolute; right: 0.7rem; top: 0.5rem; z-index: 2; display: flex; gap: 0.3rem; }
  .tam-live button { background: rgba(7,19,39,0.85); color: #9fc4ff; border: 1px solid #12305a; border-radius: 5px; font-size: 0.72rem; padding: 0.2rem 0.5rem; cursor: pointer; }
  .tam-live button.active { color: #fff; border-color: #5fb0ff; }
  .tam-hero .tam-land { fill: #07111f; stroke: #1f6fd0; stroke-width: 0.45; opacity: 1; }
  .tam-feed { background: #04070d; border-top: 1px solid #12305a; font-family: var(--mono, monospace); font-size: 0.72rem; color: #9fc4ff; padding: 0.3rem 0.6rem; min-height: 8.2rem; }
  .tam-feed div { display: grid; grid-template-columns: 5.5rem 7.5rem 1fr 2.4rem 8rem; gap: 0.5rem; padding: 0.1rem 0; white-space: nowrap; overflow: hidden; }
  .tam-feed div span { overflow: hidden; text-overflow: ellipsis; }
  .tam-feed div.nordic { color: #ff5a5a; }
  .tam-feed div.head { color: #5fb0ff; border-bottom: 1px solid #12305a; margin-bottom: 0.15rem; }
  @media (max-width: 600px) { .tam-feed div { grid-template-columns: 5rem 6rem 1fr 2rem; } .tam-feed div span:nth-child(5) { display: none; } }
  .tam-bar { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin-bottom: 0.8rem; }
  .tam-bar select, .tam-bar input, .tam-btn {
    background: var(--panel); color: var(--text); border: 1px solid var(--panel-border);
    border-radius: 6px; padding: 0.35rem 0.65rem; font-size: 0.82rem; font-family: inherit; cursor: pointer; }
  .tam-bar input { cursor: text; min-width: 11rem; }
  .tam-btn:hover { background: var(--panel-border); }
  .tam-btn.active { border-color: var(--amber); color: var(--amber); }
  .tam-sep { width: 1px; height: 1.4rem; background: var(--panel-border); margin: 0 0.2rem; }
  .tam-layout { display: grid; grid-template-columns: 250px minmax(0, 1fr); gap: 1rem; align-items: start; }
  @media (max-width: 800px) { .tam-layout { grid-template-columns: 1fr; } .tam-list { max-height: 260px; } }
  .tam-list { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; max-height: 520px; overflow-y: auto; }
  .tam-list-head { display: flex; gap: 0.4rem; padding: 0.45rem 0.6rem; border-bottom: 1px solid var(--panel-border); font-size: 0.72rem; color: var(--text-dim); align-items: center; }
  .tam-list-head button { background: none; border: none; color: var(--text-dim); cursor: pointer; font-size: 0.72rem; padding: 0.1rem 0.3rem; border-radius: 4px; }
  .tam-list-head button.active { color: var(--amber); background: rgba(232,163,61,0.12); }
  .tam-row { display: grid; grid-template-columns: 1fr auto auto; gap: 0.5rem; align-items: center; padding: 0.35rem 0.7rem; cursor: pointer; font-size: 0.83rem; }
  .tam-row:hover { background: var(--panel-border); }
  .tam-row.sel { background: rgba(232,163,61,0.16); }
  .tam-row .n { font-family: var(--mono, monospace); color: var(--text-dim); font-size: 0.78rem; }
  .tam-nord { font-size: 0.66rem; padding: 0 0.35rem; border-radius: 9px; border: 1px solid var(--amber); color: var(--amber); }
  .tam-map { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; overflow: hidden; position: relative; }
  .tam-map svg { width: 100%; height: auto; display: block; touch-action: pan-y; }
  .tam-land { fill: var(--panel-border); stroke: var(--bg, #0d1117); stroke-width: 0.5; opacity: 0.85; }
  .tam-bubble { fill: var(--amber); fill-opacity: 0.7; stroke: var(--amber); }
  .tam-bubble.nordic { stroke: var(--text); stroke-width: 1.6; fill: var(--red); }
  .tam-lbl { fill: var(--text); font-size: 9px; text-anchor: middle; pointer-events: none; paint-order: stroke; stroke: var(--panel); stroke-width: 2.5px; }
  .tam-msg { padding: 0.6rem 0.9rem; font-size: 0.8rem; color: var(--text-dim); }
  .tam-profile { margin-top: 0.9rem; }
  .tam-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 0.5rem; margin-bottom: 0.8rem; }
  .tam-kpi { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.5rem 0.7rem; }
  .tam-kpi b { display: block; font-size: 1.25rem; font-family: var(--mono, monospace); }
  .tam-kpi span { font-size: 0.72rem; color: var(--text-dim); }
  .tam-kpi.alert b { color: var(--red); }
  .tam-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; }
  .tam-h { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-dim); margin: 0.2rem 0 0.4rem; }
  .tam-bars div { display: grid; grid-template-columns: 9rem 1fr 2.2rem; gap: 0.4rem; align-items: center; font-size: 0.8rem; padding: 0.12rem 0; }
  .tam-bars span.bar { display: block; height: 6px; border-radius: 3px; background: var(--amber); min-width: 2px; }
  .tam-bars .lab { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tam-bars .v { font-family: var(--mono, monospace); text-align: right; color: var(--text-dim); font-size: 0.75rem; }
  .tam-recent { margin: 0; padding-left: 1.1rem; font-size: 0.82rem; max-height: 230px; overflow-y: auto; }
  .tam-recent li { margin-bottom: 0.25rem; }
  .tam-heat-wrap { overflow-x: auto; margin-top: 1.1rem; }
  .tam-heat { border-collapse: collapse; font-size: 0.76rem; }
  .tam-heat th { font-weight: 500; color: var(--text-dim); padding: 0.25rem 0.4rem; text-align: center; max-width: 7rem; }
  .tam-heat th.rowh { text-align: left; cursor: pointer; white-space: nowrap; color: var(--text); }
  .tam-heat th.rowh:hover { color: var(--amber); }
  .tam-heat td { width: 2.6rem; height: 1.6rem; text-align: center; font-family: var(--mono, monospace); border: 1px solid var(--panel); }
"""

_BODY = """
<div class="tam-bar">
  <label class="dim" for="tamPeriod">Period:</label>
  <select id="tamPeriod">
    <option value="30">30 dagar</option>
    <option value="90" selected>90 dagar</option>
    <option value="365">1 år</option>
    <option value="0">Allt</option>
  </select>
  <span class="tam-sep"></span>
  <button class="tam-btn tam-view active" data-view="world" type="button">Världen</button>
  <button class="tam-btn tam-view" data-view="europe" type="button">Europa</button>
  <button class="tam-btn tam-view" data-view="nordic" type="button">Norden</button>
  <button class="tam-btn" id="tamZin" type="button" title="Zooma in">＋</button>
  <button class="tam-btn" id="tamZout" type="button" title="Zooma ut">－</button>
  <span class="dim" style="font-size:0.74rem;margin-left:auto">Live spelar upp de senaste offren i tidsordning (ljuspuls = nytt offer, rött = Norden). Dra för att panorera, Ctrl + scrollhjul för att zooma. Visar var offren finns, inte var aktören sitter (ursprung finns inte i datan).</span>
</div>
<div class="tam-hero">
  <div class="tam-side"><h4>Aktiva grupper</h4><div id="tamTopGroups"></div></div>
  <div>
    <div class="tam-stage" id="tamStage">
      <div class="tam-tag">Hotaktörskarta<b>RANSOMWARE LIVE-ÅTERSPELNING</b></div>
      <div class="tam-live"><button type="button" id="tamModeLive" class="active">Live</button><button type="button" id="tamModeTot">Totalt</button><button type="button" id="tamPlay">⏸</button></div>
      <div id="tamMap"></div><canvas id="tamCv"></canvas>
      <div id="tamMsg" class="tam-msg" style="display:none;position:absolute;left:0;bottom:0"></div>
    </div>
    <div class="tam-feed" id="tamFeed"></div>
  </div>
  <div class="tam-side"><h4>Mål (länder)</h4><div id="tamTopTargets"></div></div>
</div>
<div class="tam-layout" style="margin-top:1rem">
  <div class="tam-list">
    <div class="tam-list-head">
      <span>Sortera:</span>
      <button type="button" id="tamSortTotal" class="active">Totalt</button>
      <button type="button" id="tamSortNordic">Norden</button>
      <input id="tamFilter" placeholder="Filtrera..." style="margin-left:auto;min-width:0;width:6.5rem;padding:0.15rem 0.4rem;font-size:0.72rem;background:var(--panel);color:var(--text);border:1px solid var(--panel-border);border-radius:5px">
    </div>
    <div id="tamRows"></div>
  </div>
  <div class="tam-profile" id="tamProfile" style="margin-top:0"></div>
</div>
<div class="tam-heat-wrap"><div class="tam-h">Aktör × bransch (de mest aktiva grupperna i vald period, klicka på ett namn för att välja)</div><div id="tamHeat"></div></div>
"""

_JS = """
(function () {
  var DATA = __DATA__;
  var NORDIC = { SE: 1, NO: 1, DK: 1, FI: 1, IS: 1 };
  var W = 800, H = 440;
  var state = { days: 90, actor: null, sort: "total", filter: "" };
  var proj = null, path = null, zoomB = null, gMap = null, gBub = null, svg = null, curK = 1, ready = false;
  var BOX = { europe: [[-12, 34], [40, 71]], nordic: [[3, 54.5], [32, 71.5]] };
  var $ = function (id) { return document.getElementById(id); };
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  function rowsInPeriod() {
    if (!state.days) return DATA.rows;
    var cut = new Date(Date.now() - state.days * 86400000).toISOString().slice(0, 10);
    return DATA.rows.filter(function (r) { return !r[3] || r[3] >= cut; });
  }
  function tally(rows, idx) {
    var m = {};
    rows.forEach(function (r) { var k = r[idx] || ""; if (k) m[k] = (m[k] || 0) + 1; });
    return Object.keys(m).map(function (k) { return [k, m[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
  }
  function actors(rows) {
    var m = {};
    rows.forEach(function (r) {
      var a = m[r[0]] || (m[r[0]] = { name: r[0], n: 0, nordic: 0 });
      a.n++; if (NORDIC[r[1]]) a.nordic++;
    });
    return Object.keys(m).map(function (k) { return m[k]; });
  }

  function renderList(rows) {
    var list = actors(rows);
    var f = state.filter.toLowerCase();
    if (f) list = list.filter(function (a) { return a.name.toLowerCase().indexOf(f) >= 0; });
    list.sort(function (a, b) { return state.sort === "nordic" ? (b.nordic - a.nordic || b.n - a.n) : (b.n - a.n); });
    if (state.sort === "nordic") list = list.filter(function (a) { return a.nordic > 0; });
    var html = '<div class="tam-row' + (state.actor ? "" : " sel") + '" data-actor=""><span>Alla aktörer</span><span></span><span class="n">' + rows.length + '</span></div>';
    list.slice(0, 80).forEach(function (a) {
      html += '<div class="tam-row' + (state.actor === a.name ? " sel" : "") + '" data-actor="' + esc(a.name) + '"><span>' + esc(a.name) + '</span>' +
        (a.nordic ? '<span class="tam-nord" title="Nordiska offer">' + a.nordic + ' Norden</span>' : '<span></span>') +
        '<span class="n">' + a.n + '</span></div>';
    });
    if (!list.length) html += '<div class="tam-msg">Inga aktörer i vald period.</div>';
    $("tamRows").innerHTML = html;
  }

  function bars(pairs, max, limit) {
    if (!pairs.length) return '<div class="dim" style="display:block">Ingen data.</div>';
    return pairs.slice(0, limit).map(function (p) {
      return '<div><span class="lab" title="' + esc(p[0]) + '">' + esc(p[0]) + '</span><span><span class="bar" style="width:' + Math.max(3, p[1] / max * 100) + '%"></span></span><span class="v">' + p[1] + '</span></div>';
    }).join("");
  }

  function renderProfile(rows) {
    var sel = state.actor ? rows.filter(function (r) { return r[0] === state.actor; }) : rows;
    var title = state.actor ? esc(state.actor) : "Alla aktörer";
    var countries = tally(sel, 1), sectors = tally(sel, 2);
    var nordic = sel.filter(function (r) { return NORDIC[r[1]]; });
    var dates = sel.map(function (r) { return r[3]; }).filter(Boolean).sort();
    var recent = sel.slice().sort(function (a, b) { return (b[3] || "").localeCompare(a[3] || ""); }).slice(0, 14);
    var nGroups = state.actor ? 1 : actors(sel).length;
    var h = '<div class="tam-h" style="font-size:0.9rem;text-transform:none;color:var(--text)"><b>' + title + '</b></div>';
    h += '<div class="tam-kpis">' +
      '<div class="tam-kpi"><b>' + sel.length + '</b><span>offer i perioden</span></div>' +
      '<div class="tam-kpi"><b>' + countries.length + '</b><span>länder</span></div>' +
      '<div class="tam-kpi' + (nordic.length ? " alert" : "") + '"><b>' + nordic.length + '</b><span>nordiska offer</span></div>' +
      (state.actor ? '<div class="tam-kpi"><b style="font-size:0.95rem">' + esc(dates[0] || "?") + '</b><span>första offret</span></div><div class="tam-kpi"><b style="font-size:0.95rem">' + esc(dates[dates.length - 1] || "?") + '</b><span>senaste offret</span></div>'
        : '<div class="tam-kpi"><b>' + nGroups + '</b><span>aktiva grupper</span></div>') + '</div>';
    h += '<div class="tam-cols"><div><div class="tam-h">Vanligaste länder</div><div class="tam-bars">' + bars(countries, countries.length ? countries[0][1] : 1, 8) + '</div></div>' +
      '<div><div class="tam-h">Vanligaste branscher</div><div class="tam-bars">' + bars(sectors, sectors.length ? sectors[0][1] : 1, 8) + '</div></div>' +
      '<div><div class="tam-h">' + (nordic.length ? "Nordiska offer (senaste)" : "Senaste offer") + '</div><ul class="tam-recent">' +
      (nordic.length ? nordic.slice().sort(function (a, b) { return (b[3] || "").localeCompare(a[3] || ""); }).slice(0, 14) : recent).map(function (r) {
        return '<li>' + esc(r[4]) + ' <span class="dim">(' + esc(r[1] || "?") + (state.actor ? "" : ", " + esc(r[0])) + (r[3] ? ", " + esc(r[3]) : "") + ')</span></li>';
      }).join("") + '</ul></div></div>';
    $("tamProfile").innerHTML = h;
  }

  function renderHeat(rows) {
    var top = actors(rows).sort(function (a, b) { return b.n - a.n; }).slice(0, 12);
    var secs = tally(rows, 2).slice(0, 10).map(function (s) { return s[0]; });
    if (!top.length || !secs.length) { $("tamHeat").innerHTML = '<div class="tam-msg">Ingen branschdata i vald period.</div>'; return; }
    var cell = {}, max = 1;
    rows.forEach(function (r) {
      if (!r[2]) return;
      var k = r[0] + "|" + r[2]; cell[k] = (cell[k] || 0) + 1; if (cell[k] > max) max = cell[k];
    });
    var h = '<table class="tam-heat"><tr><th></th>' + secs.map(function (s) { return '<th title="' + esc(s) + '">' + esc(s.length > 14 ? s.slice(0, 13) + "…" : s) + '</th>'; }).join("") + '</tr>';
    top.forEach(function (a) {
      h += '<tr><th class="rowh" data-actor="' + esc(a.name) + '">' + esc(a.name) + '</th>';
      secs.forEach(function (s) {
        var v = cell[a.name + "|" + s] || 0;
        h += '<td style="background:rgba(232,163,61,' + (v ? (0.12 + 0.78 * v / max).toFixed(2) : 0) + ')">' + (v || "") + '</td>';
      });
      h += '</tr>';
    });
    $("tamHeat").innerHTML = h + '</table>';
  }

  // ---- karta
  function drawBubbles(rows) {
    if (!ready) return;
    var sel = state.actor ? rows.filter(function (r) { return r[0] === state.actor; }) : rows;
    var data = tally(sel, 1).filter(function (c) { return DATA.centroids[c[0]]; }).map(function (c) {
      var ll = DATA.centroids[c[0]], p = proj([ll[1], ll[0]]);
      return { cc: c[0], n: c[1], x: p[0], y: p[1] };
    });
    var max = data.length ? data[0].n : 1;
    var rad = d3.scalePow().exponent(0.5).domain([0, max]).range([3, 20]);
    gBub.selectAll("*").remove();
    var g = gBub.selectAll("g").data(data.slice().reverse()).enter().append("g").attr("transform", function (d) { return "translate(" + d.x + "," + d.y + ")"; });
    g.append("title").text(function (d) { return d.cc + ": " + d.n + " offer"; });
    g.append("circle").attr("class", function (d) { return "tam-bubble" + (NORDIC[d.cc] ? " nordic" : ""); }).attr("data-r", function (d) { return rad(d.n); }).attr("r", function (d) { return rad(d.n); });
    g.append("text").attr("class", "tam-lbl").attr("data-rank", function (d) { return data.indexOf(d); }).attr("data-r", function (d) { return rad(d.n); })
      .text(function (d) { return d.cc + " " + d.n; });
    applyScale();
    var miss = tally(sel, 1).filter(function (c) { return !DATA.centroids[c[0]]; }).reduce(function (s, c) { return s + c[1]; }, 0);
    var msg = $("tamMsg");
    if (miss) { msg.style.display = ""; msg.textContent = miss + " offer saknar landkod eller har ett land som inte kan placeras på kartan."; } else { msg.style.display = "none"; }
  }
  function applyScale() {
    if (!gBub) return;
    var k = curK, f = 1 / Math.pow(k, 0.8), show = 5 + (k - 1) * 6;
    gBub.selectAll("circle").attr("r", function () { return (+this.getAttribute("data-r")) * f; })
      .style("stroke-width", function () { return ((this.classList.contains("nordic") ? 1.6 : 1) / k) + "px"; });
    gBub.selectAll("text").attr("y", function () { return -(+this.getAttribute("data-r")) * f - 3 / k; })
      .style("font-size", (9 / k) + "px").style("stroke-width", (2.5 / k) + "px")
      .style("display", function () { return (+this.getAttribute("data-rank")) < show ? "" : "none"; });
  }
  function goBox(box) {
    if (!ready) return;
    var a = proj(box[0]), b = proj(box[1]);
    var x0 = Math.min(a[0], b[0]), x1 = Math.max(a[0], b[0]), y0 = Math.min(a[1], b[1]), y1 = Math.max(a[1], b[1]);
    var k = Math.max(1, Math.min(40, 0.9 / Math.max((x1 - x0) / W, (y1 - y0) / H)));
    svg.transition().duration(450).call(zoomB.transform, d3.zoomIdentity.translate(W / 2 - k * (x0 + x1) / 2, H / 2 - k * (y0 + y1) / 2).scale(k));
  }
  function loadScript(src) {
    return new Promise(function (res, rej) {
      var s = document.createElement("script"); s.src = src; s.onload = res; s.onerror = rej; document.head.appendChild(s);
    });
  }
  function initMap() {
    var need = [];
    if (!window.d3) need.push("https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js");
    var chain = need.reduce(function (p, s) { return p.then(function () { return loadScript(s); }); }, Promise.resolve());
    chain.then(function () { return window.topojson ? 0 : loadScript("https://cdnjs.cloudflare.com/ajax/libs/topojson/3.0.2/topojson.min.js"); })
      .then(function () { return d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"); })
      .then(function (world) {
        var land = topojson.feature(world, world.objects.countries);
        proj = d3.geoNaturalEarth1().fitSize([W, H], land);
        path = d3.geoPath(proj);
        svg = d3.select("#tamMap").append("svg").attr("viewBox", "0 0 " + W + " " + H);
        gMap = svg.append("g");
        gMap.selectAll("path").data(land.features).enter().append("path").attr("class", "tam-land").attr("d", path);
        gBub = gMap.append("g");
        zoomB = d3.zoom().scaleExtent([1, 40]).translateExtent([[0, 0], [W, H]])
          .filter(function (e) { return (e.type !== "wheel" || e.ctrlKey || e.metaKey) && !e.button; })
          .on("zoom", function (e) { curK = e.transform.k; live.t = { x: e.transform.x, y: e.transform.y, k: e.transform.k }; gMap.attr("transform", e.transform); applyScale(); });
        svg.call(zoomB);
        ready = true;
        gBub.style("display", live.on ? "none" : "");
        sizeCanvas();
        drawBubbles(rowsInPeriod());
      }).catch(function () {
        var m = $("tamMsg"); m.style.display = ""; m.textContent = "Kartlagret kunde inte laddas (D3/world-atlas via CDN). Lista, profil och värmekarta fungerar ändå.";
      });
  }


  // ---- live-återspelning (canvas ovanpå kartan)
  var live = { on: true, play: true, ev: [], idx: 0, active: [], last: 0, feed: [], t: { x: 0, y: 0, k: 1 }, dpr: 1, acc: 0 };
  var PAL = ["#ff9f1c", "#2ec4b6", "#e71d36", "#9b5de5", "#00bbf9", "#f15bb5", "#fee440", "#80ed99", "#ff6b35", "#4cc9f0"];
  function colorOf(name) { var h = 0; for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0; return PAL[h % PAL.length]; }
  function jitter(s, i) { var h = 0; for (var j = 0; j < s.length; j++) h = (h * 33 + s.charCodeAt(j)) >>> 0; return ((h >> (i * 5)) % 1000) / 1000 - 0.5; }
  function buildEvents(rows) {
    var sel = state.actor ? rows.filter(function (r) { return r[0] === state.actor; }) : rows;
    sel = sel.filter(function (r) { return DATA.centroids[r[1]]; }).sort(function (a, b) { return (a[3] || "").localeCompare(b[3] || ""); });
    live.ev = sel.slice(-160); live.idx = 0; live.active = []; live.feed = []; renderFeed(); renderSides(rows);
  }
  function fmtRow(e, cls, head) {
    return '<div class="' + (cls || "") + '"><span>' + esc(e[3] || "") + '</span><span>' + esc(e[0]) + '</span><span>' + esc(e[4]) + '</span><span>' + esc(e[1]) + '</span><span>' + esc(e[2] || "") + '</span></div>';
  }
  function renderFeed() {
    var h = '<div class="head"><span>Datum</span><span>Grupp</span><span>Offer</span><span>Land</span><span>Bransch</span></div>';
    live.feed.slice(-6).reverse().forEach(function (e) { h += fmtRow(e, NORDIC[e[1]] ? "nordic" : ""); });
    if (!live.feed.length) h += '<div><span>Väntar på händelser...</span></div>';
    $("tamFeed").innerHTML = h;
  }
  function renderSides(rows) {
    var sel = state.actor ? rows.filter(function (r) { return r[0] === state.actor; }) : rows;
    var g = actors(sel).sort(function (a, b) { return b.n - a.n; }).slice(0, 9);
    $("tamTopGroups").innerHTML = g.map(function (a) { return '<div class="r"><b>' + a.n + '</b><span style="color:' + colorOf(a.name) + '">● ' + esc(a.name) + '</span></div>'; }).join("") || "Ingen data";
    $("tamTopTargets").innerHTML = tally(sel, 1).slice(0, 9).map(function (c) { return '<div class="r' + (NORDIC[c[0]] ? " nordic" : "") + '"><b>' + c[1] + '</b><span>' + esc(c[0]) + '</span></div>'; }).join("") || "Ingen data";
  }
  function sizeCanvas() {
    var cv = $("tamCv"), st = $("tamStage"); if (!cv || !st) return;
    live.dpr = window.devicePixelRatio || 1;
    cv.width = st.clientWidth * live.dpr; cv.height = st.clientHeight * live.dpr;
  }
  function spawn(r) {
    var ll = DATA.centroids[r[1]], p = proj([ll[1] + jitter(r[4], 1) * 4, ll[0] + jitter(r[4], 2) * 3]);
    var e = { x: p[0], y: p[1], born: performance.now(), col: NORDIC[r[1]] ? "#ff3b3b" : colorOf(r[0]), nordic: !!NORDIC[r[1]], row: r };
    live.active.push(e); live.feed.push(r); if (live.feed.length > 40) live.feed.shift(); renderFeed();
    if (live.active.length > 220) live.active.shift();
  }
  function frame(now) {
    requestAnimationFrame(frame);
    var cv = $("tamCv"); if (!cv || !ready || !cv.width) return;
    var ctx = cv.getContext("2d"), st = $("tamStage"), sc = (st.clientWidth / W) * live.dpr;
    ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.clearRect(0, 0, cv.width, cv.height);
    if (!live.on) return;
    if (live.play && live.ev.length) {
      if (!live.last) live.last = now;
      live.acc += now - live.last; live.last = now;
      var step = 450;
      while (live.acc > step) { live.acc -= step; spawn(live.ev[live.idx]); live.idx = (live.idx + 1) % live.ev.length; }
    } else live.last = 0;
    ctx.globalCompositeOperation = "lighter";
    var t = live.t;
    live.active.forEach(function (e) {
      var age = (now - e.born) / 1000, X = (e.x * t.k + t.x) * sc, Y = (e.y * t.k + t.y) * sc;
      var base = 2.6 * live.dpr * (e.nordic ? 1.5 : 1);
      var a = Math.max(0.3, 1 - age / 40);
      ctx.fillStyle = e.col; ctx.globalAlpha = a * 0.9;
      ctx.beginPath(); ctx.arc(X, Y, base, 0, 6.2832); ctx.fill();
      for (var i = 0; i < 2; i++) {
        var ph = age - i * 0.9; if (ph < 0 || ph > 3) continue;
        ctx.strokeStyle = e.col; ctx.globalAlpha = (1 - ph / 3) * 0.8; ctx.lineWidth = (e.nordic ? 2 : 1.4) * live.dpr;
        ctx.beginPath(); ctx.arc(X, Y, base + ph * (e.nordic ? 15 : 10) * live.dpr, 0, 6.2832); ctx.stroke();
      }
    });
    ctx.globalAlpha = 1; ctx.globalCompositeOperation = "source-over";
  }
  function setMode(on) {
    live.on = on; $("tamModeLive").classList.toggle("active", on); $("tamModeTot").classList.toggle("active", !on);
    if (gBub) gBub.style("display", on ? "none" : "");
    if (on) { buildEvents(rowsInPeriod()); }
  }

  function renderAll() {
    var rows = rowsInPeriod();
    renderList(rows); renderProfile(rows); renderHeat(rows); drawBubbles(rows); buildEvents(rows);
  }
  function select(name) { state.actor = name || null; renderAll(); }

  $("tamRows").addEventListener("click", function (e) { var r = e.target.closest(".tam-row"); if (r) select(r.getAttribute("data-actor")); });
  $("tamHeat").addEventListener("click", function (e) { var r = e.target.closest(".rowh"); if (r) select(r.getAttribute("data-actor")); });
  $("tamPeriod").addEventListener("change", function () { state.days = +this.value; renderAll(); });
  $("tamFilter").addEventListener("input", function () { state.filter = this.value; renderList(rowsInPeriod()); });
  $("tamSortTotal").addEventListener("click", function () { state.sort = "total"; $("tamSortTotal").classList.add("active"); $("tamSortNordic").classList.remove("active"); renderList(rowsInPeriod()); });
  $("tamSortNordic").addEventListener("click", function () { state.sort = "nordic"; $("tamSortNordic").classList.add("active"); $("tamSortTotal").classList.remove("active"); renderList(rowsInPeriod()); });
  document.querySelectorAll(".tam-view").forEach(function (b) {
    b.addEventListener("click", function () {
      document.querySelectorAll(".tam-view").forEach(function (x) { x.classList.toggle("active", x === b); });
      if (!ready) return;
      var v = b.getAttribute("data-view");
      if (v === "world") svg.transition().duration(450).call(zoomB.transform, d3.zoomIdentity); else goBox(BOX[v]);
    });
  });
  $("tamZin").addEventListener("click", function () { if (ready) svg.transition().duration(250).call(zoomB.scaleBy, 1.6); });
  $("tamZout").addEventListener("click", function () { if (ready) svg.transition().duration(250).call(zoomB.scaleBy, 1 / 1.6); });

  $("tamModeLive").addEventListener("click", function () { setMode(true); });
  $("tamModeTot").addEventListener("click", function () { setMode(false); });
  $("tamPlay").addEventListener("click", function () { live.play = !live.play; this.textContent = live.play ? "⏸" : "▶"; });
  window.addEventListener("resize", sizeCanvas);
  renderAll();
  initMap();
  requestAnimationFrame(frame);
})();
"""


def _collect(db_path: str) -> list:
    conn = sqlite3.connect(db_path)
    raw = []
    for day_expr in ("COALESCE(NULLIF(attack_date, ''), substr(first_seen, 1, 10))", "attack_date"):
        try:
            raw = conn.execute(
                f"SELECT group_name, country, sector, {day_expr} AS day, victim FROM ransomware_victims "
                "WHERE group_name IS NOT NULL AND group_name != '' ORDER BY id DESC LIMIT ?",
                (MAX_ROWS,),
            ).fetchall()
            break
        except sqlite3.Error:
            continue
    conn.close()

    # Slå ihop skillnader i skiftläge mellan källor ("Qilin"/"qilin"): visa vanligaste stavningen.
    spelling: dict = {}
    for g, *_ in raw:
        spelling.setdefault(g.strip().lower(), {}).setdefault(g.strip(), 0)
        spelling[g.strip().lower()][g.strip()] += 1
    canon = {k: max(v.items(), key=lambda x: x[1])[0] for k, v in spelling.items()}
    rows = []
    for g, country, sector, day, victim in raw:
        rows.append([
            canon[g.strip().lower()],
            (country or "").strip().upper(),
            (sector or "").strip(),
            (day or "")[:10],
            (victim or "").strip()[:80],
        ])
    return rows


def build_actor_map_block(db_path: str = DB_PATH, centroids: dict = None) -> str:
    rows = _collect(db_path)
    if not rows:
        return '<p class="empty">Ingen aktörsdata ännu (fylls när ransomware-offer har samlats in).</p>'
    centroids = {k: [v[0], v[1]] for k, v in (centroids or {}).items()}
    data = json.dumps({"rows": rows, "centroids": centroids}, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return _BODY + "<script>" + _JS.replace("__DATA__", data) + "</script>"
