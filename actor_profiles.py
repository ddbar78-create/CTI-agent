"""
Aktörsprofiler — en profil per ransomware-grupp och malware-familj, direkt
i dashboarden. Ingen ny datainsamling: profilerna byggs i webbläsaren av
samma data som sökfunktionen redan bäddat in (window.__ctiData, se
search_report.py), så sektionen 'Sök & rapport' måste ligga FÖRE den här.

Grupp-profil:   antal offer, tidsintervall, länder, sektorer, Norden-offer,
                aktivitet per vecka (12 v), senaste offer, relaterade artiklar.
Familj-profil:  ATT&CK-kategori och tekniker, IOC-typer, källor, senaste
                IOC:er, relaterade artiklar.
Båda kan laddas ner som Markdown-rapport eller öppnas i sökfunktionen.
"""

ACTOR_CSS = """
  .ap-tabs { display: flex; gap: 0.4rem; margin-bottom: 0.7rem; flex-wrap: wrap; align-items: center; }
  .ap-layout { display: grid; grid-template-columns: 260px minmax(0, 1fr); gap: 1rem; align-items: start; }
  .ap-list {
    background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px;
    max-height: 520px; overflow-y: auto;
  }
  .ap-row {
    display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 0.5rem; padding: 0.4rem 0.8rem;
    cursor: pointer; font-size: 0.84rem; border-bottom: 1px solid var(--panel-border);
  }
  .ap-row:hover { background: var(--panel-border); }
  .ap-row.selected { background: rgba(232,163,61,0.15); }
  .ap-row .nm { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ap-profile {
    background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px;
    padding: 1rem 1.2rem; min-height: 200px; font-size: 0.86rem;
  }
  .ap-title { font-size: 1.15rem; font-weight: 600; margin-bottom: 0.2rem; }
  .ap-kpis { display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 0.8rem 0; }
  .ap-kpi { background: var(--bg); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.5rem 0.8rem; min-width: 90px; }
  .ap-kpi b { display: block; font-size: 1.2rem; font-family: var(--mono); }
  .ap-kpi span { font-size: 0.72rem; color: var(--text-dim); }
  .ap-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 1.2rem; }
  .ap-profile h4 { font-size: 0.8rem; margin: 1rem 0 0.4rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.04em; }
  .ap-profile ul { margin: 0; padding-left: 1.1rem; }
  .ap-profile li { margin-bottom: 0.25rem; }
  .ap-actions { margin-top: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
  @media (max-width: 800px) { .ap-layout, .ap-cols { grid-template-columns: 1fr; } .ap-list { max-height: 260px; } }
"""

_TEMPLATE = r"""
<div id="apRoot">
  <div class="ap-tabs">
    <button class="map-btn active" data-tab="groups">Ransomware-grupper</button>
    <button class="map-btn" data-tab="families">Malware-familjer</button>
    <input type="search" id="apFilter" class="sr-input" style="max-width:260px;padding:0.4rem 0.7rem;font-size:0.85rem" placeholder="Filtrera lista…">
  </div>
  <div class="ap-layout">
    <div class="ap-list" id="apList"></div>
    <div class="ap-profile" id="apProfile"><span class="dim">Välj en grupp eller familj i listan.</span></div>
  </div>
</div>
<script>
(function() {
  const D = window.__ctiData;
  const root = document.getElementById("apRoot");
  if (!D) { root.innerHTML = '<p class="empty">Aktörsprofiler kräver sökdatan (sektionen Sök &amp; rapport).</p>'; return; }
  const NORDIC = new Set(["SE", "NO", "DK", "FI", "IS"]);
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const familyOf = v => { const m = String(v).match(/\[([^\],]+),/); return m ? m[1].trim() : ""; };
  const cleanValue = v => String(v).split(" [")[0].trim();
  const dayMs = 86400000;

  // ---- aggregera ----
  const groups = {};
  D.victims.forEach(v => {
    const g = (groups[v[0]] = groups[v[0]] || { name: v[0], victims: [], countries: {}, sectors: {}, last: "" });
    g.victims.push(v);
    if (v[2]) g.countries[v[2]] = (g.countries[v[2]] || 0) + 1;
    if (v[3]) g.sectors[v[3]] = (g.sectors[v[3]] || 0) + 1;
    if (v[4] && v[4] > g.last) g.last = v[4];
  });
  const families = {};
  D.iocs.forEach(x => {
    const f = familyOf(x[1]);
    if (!f) return;
    const e = (families[f] = families[f] || { name: f, n: 0, types: {}, feeds: {}, recent: [] });
    e.n++;
    e.types[x[0]] = (e.types[x[0]] || 0) + 1;
    if (x[2]) e.feeds[x[2]] = (e.feeds[x[2]] || 0) + 1;
    if (e.recent.length < 25) e.recent.push(x);
  });
  const groupList = Object.values(groups).sort((a, b) => b.victims.length - a.victims.length);
  const famList = Object.values(families).sort((a, b) => b.n - a.n);

  let tab = groupList.length ? "groups" : "families";
  let selected = null;
  const listEl = document.getElementById("apList");
  const profEl = document.getElementById("apProfile");
  const filterEl = document.getElementById("apFilter");

  const top = (obj, n) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n);
  const bars = (entries) => {
    const max = entries.length ? entries[0][1] : 1;
    return entries.map(([k, v]) => `<div class="bar-row"><span class="bar-label" style="width:90px;overflow:hidden;text-overflow:ellipsis" title="${esc(k)}">${esc(k)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(4, v / max * 100)}%"></div></div><span class="bar-count">${v}</span></div>`).join("");
  };
  const related = name => {
    const n = name.toLowerCase();
    return D.articles.filter(a => (a[0] + " " + a[4]).toLowerCase().includes(n)).slice(0, 10);
  };
  const articleList = arts => arts.length
    ? "<ul>" + arts.map(a => `<li><a href="${esc(a[1])}" target="_blank" rel="noopener">${esc(a[0])}</a> <span class="dim">${esc(a[2])}</span></li>`).join("") + "</ul>"
    : '<span class="dim">Inga artiklar i det insamlade urvalet.</span>';
  const techLink = t => {
    const m = String(t).match(/T\d{4}(?:\.\d{3})?/);
    return m ? `<a href="https://attack.mitre.org/techniques/${m[0].replace(".", "/")}/" target="_blank" rel="noopener">${esc(t)}</a>` : esc(t);
  };

  function weekly(victims) {
    const now = Date.now(), buckets = new Array(12).fill(0);
    victims.forEach(v => {
      const t = Date.parse(v[4]);
      if (isNaN(t)) return;
      const i = Math.floor((now - t) / (7 * dayMs));
      if (i >= 0 && i < 12) buckets[11 - i]++;
    });
    const max = Math.max(1, ...buckets);
    const w = 18, gap = 4, h = 50;
    const rects = buckets.map((b, i) =>
      `<rect x="${i * (w + gap)}" y="${h - b / max * h}" width="${w}" height="${Math.max(b ? 2 : 0, b / max * h)}" fill="#e8a33d"><title>${b} offer (${11 - i} v sedan)</title></rect>`).join("");
    return { svg: `<svg viewBox="0 0 ${12 * (w + gap)} ${h}" width="100%" height="60" preserveAspectRatio="none">${rects}</svg>`, total: buckets.reduce((a, b) => a + b, 0) };
  }

  function download(name, text) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/markdown;charset=utf-8" }));
    a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  const slug = s => s.toLowerCase().replace(/[^a-z0-9åäö]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "profil";
  const openInSearch = name => {
    if (window.ctiSearch) { window.ctiSearch(name); document.getElementById("sec-search").scrollIntoView({ behavior: "smooth" }); }
  };

  function groupProfile(g) {
    const dates = g.victims.map(v => v[4]).filter(Boolean).sort();
    const nordic = g.victims.filter(v => NORDIC.has(v[2]));
    const wk = weekly(g.victims);
    const recent = g.victims.slice().sort((a, b) => (b[4] || "").localeCompare(a[4] || "")).slice(0, 25);
    const arts = related(g.name);
    const fam = families[g.name] || Object.values(families).find(f => f.name.toLowerCase() === g.name.toLowerCase());
    profEl.innerHTML = `
      <div class="ap-title">${esc(g.name)}</div>
      <div class="dim">Ransomware-grupp (enligt ransomware.live)</div>
      <div class="ap-kpis">
        <div class="ap-kpi"><b>${g.victims.length}</b><span>offer i urvalet</span></div>
        <div class="ap-kpi"><b>${nordic.length}</b><span>i Norden</span></div>
        <div class="ap-kpi"><b>${Object.keys(g.countries).length}</b><span>länder</span></div>
        <div class="ap-kpi"><b>${wk.total}</b><span>senaste 12 v</span></div>
        <div class="ap-kpi"><b>${esc(dates.length ? dates[dates.length - 1] : "–")}</b><span>senaste datum</span></div>
      </div>
      <h4>Aktivitet per vecka (12 v)</h4>${wk.svg}<div class="dim" style="display:flex;justify-content:space-between;font-size:0.7rem"><span>12 v sedan</span><span>nu</span></div>
      <div class="ap-cols">
        <div><h4>Länder</h4>${bars(top(g.countries, 8)) || '<span class="dim">–</span>'}</div>
        <div><h4>Sektorer</h4>${bars(top(g.sectors, 8)) || '<span class="dim">–</span>'}</div>
      </div>
      ${nordic.length ? `<h4>Offer i Norden</h4><ul>${nordic.slice().sort((a, b) => (b[4] || "").localeCompare(a[4] || "")).slice(0, 15).map(v => `<li>${esc(v[1])} <span class="dim">(${esc(v[2])}${v[4] ? ", " + esc(v[4]) : ""})</span></li>`).join("")}</ul>` : ""}
      <h4>Senaste offer</h4>
      <ul>${recent.map(v => `<li>${esc(v[1])} <span class="dim">${esc(v[2])}${v[3] ? " · " + esc(v[3]) : ""}${v[4] ? " · " + esc(v[4]) : ""}</span></li>`).join("")}</ul>
      ${fam ? `<h4>Malware-koppling</h4><p>Namnet förekommer även som malware-familj (${fam.n} IOCs). <a href="#" id="apSwitchFam">Visa familjeprofil</a></p>` : ""}
      <h4>Relaterade artiklar</h4>${articleList(arts)}
      <div class="ap-actions">
        <button class="map-btn" id="apMd">⬇ Profil som Markdown</button>
        <button class="map-btn" id="apSearch">🔎 Öppna i Sök &amp; rapport</button>
      </div>`;
    document.getElementById("apMd").onclick = () => {
      const L = [`# Aktörsprofil: ${g.name}`, "", `Ransomware-grupp. Sammanställd ${new Date().toISOString().slice(0, 10)} av CTI-agenten (urval: ${g.victims.length} offer).`, "",
        "## Nyckeltal", `- Offer i urvalet: ${g.victims.length}`, `- Offer i Norden: ${nordic.length}`, `- Länder: ${Object.keys(g.countries).length}`, `- Aktivitet senaste 12 veckorna: ${wk.total}`, "",
        "## Länder", ...top(g.countries, 10).map(([k, v]) => `- ${k}: ${v}`), "",
        "## Sektorer", ...top(g.sectors, 10).map(([k, v]) => `- ${k}: ${v}`), "",
        "## Senaste offer", ...recent.map(v => `- ${v[1]} (${v[2]}${v[3] ? ", " + v[3] : ""}${v[4] ? ", " + v[4] : ""})`), ""];
      if (nordic.length) L.push("## Offer i Norden", ...nordic.map(v => `- ${v[1]} (${v[2]}${v[4] ? ", " + v[4] : ""})`), "");
      if (arts.length) L.push("## Relaterade artiklar", ...arts.map(a => `- [${a[0]}](${a[1]}) – ${a[2]}`), "");
      download("profil-" + slug(g.name) + ".md", L.join("\n"));
    };
    document.getElementById("apSearch").onclick = () => openInSearch(g.name);
    const sw = document.getElementById("apSwitchFam");
    if (sw) sw.onclick = e => { e.preventDefault(); tab = "families"; selected = fam.name; setTab(); showProfile(); };
  }

  function famProfile(f) {
    const meta = D.families[f.name] || { cat: "", tech: [] };
    const arts = related(f.name);
    const grp = groups[f.name];
    profEl.innerHTML = `
      <div class="ap-title">${esc(f.name)}</div>
      <div class="dim">Malware-familj${meta.cat ? " · " + esc(meta.cat) : ""} (enligt ThreatFox/abuse.ch m.fl.)</div>
      <div class="ap-kpis">
        <div class="ap-kpi"><b>${f.n}</b><span>IOCs i urvalet</span></div>
        <div class="ap-kpi"><b>${Object.keys(f.types).length}</b><span>IOC-typer</span></div>
        <div class="ap-kpi"><b>${Object.keys(f.feeds).length}</b><span>källor</span></div>
      </div>
      <h4>ATT&amp;CK (kategoribaserad approximation)</h4>
      ${meta.tech.length ? "<ul>" + meta.tech.map(t => `<li>${techLink(t)}</li>`).join("") + "</ul>" : '<span class="dim">Ingen mappning.</span>'}
      <div class="ap-cols">
        <div><h4>IOC-typer</h4>${bars(top(f.types, 8))}</div>
        <div><h4>Källor</h4>${bars(top(f.feeds, 8))}</div>
      </div>
      <h4>Senaste IOCs</h4>
      <ul>${f.recent.map(x => `<li class="mono ioc-value"><span class="dim">${esc(x[0])}</span> ${esc(cleanValue(x[1]))}</li>`).join("")}</ul>
      ${grp ? `<h4>Ransomware-koppling</h4><p>Namnet förekommer även som ransomware-grupp (${grp.victims.length} offer). <a href="#" id="apSwitchGrp">Visa gruppprofil</a></p>` : ""}
      <h4>Relaterade artiklar</h4>${articleList(arts)}
      <div class="ap-actions">
        <button class="map-btn" id="apMd">⬇ Profil som Markdown</button>
        <button class="map-btn" id="apSearch">🔎 Öppna i Sök &amp; rapport</button>
      </div>`;
    document.getElementById("apMd").onclick = () => {
      const L = [`# Malware-profil: ${f.name}`, "", `Sammanställd ${new Date().toISOString().slice(0, 10)} av CTI-agenten (urval: ${f.n} IOCs).`, "",
        `- Kategori: ${meta.cat || "okänd"}`, "", "## ATT&CK (approximation)", ...(meta.tech.length ? meta.tech.map(t => `- ${t}`) : ["- ingen mappning"]), "",
        "## IOC-typer", ...top(f.types, 10).map(([k, v]) => `- ${k}: ${v}`), "",
        "## Senaste IOCs (odefangade – hantera försiktigt)", "```", ...f.recent.map(x => cleanValue(x[1])), "```", ""];
      if (arts.length) L.push("## Relaterade artiklar", ...arts.map(a => `- [${a[0]}](${a[1]}) – ${a[2]}`), "");
      download("profil-" + slug(f.name) + ".md", L.join("\n"));
    };
    document.getElementById("apSearch").onclick = () => openInSearch(f.name);
    const sw = document.getElementById("apSwitchGrp");
    if (sw) sw.onclick = e => { e.preventDefault(); tab = "groups"; selected = grp.name; setTab(); showProfile(); };
  }

  function showProfile() {
    const src = tab === "groups" ? groups : families;
    const item = src[selected];
    if (!item) { profEl.innerHTML = '<span class="dim">Välj en grupp eller familj i listan.</span>'; return; }
    tab === "groups" ? groupProfile(item) : famProfile(item);
    renderList();
  }

  function renderList() {
    const q = filterEl.value.trim().toLowerCase();
    const items = (tab === "groups" ? groupList : famList).filter(x => !q || x.name.toLowerCase().includes(q));
    listEl.innerHTML = items.length ? items.map(x => {
      const n = tab === "groups" ? x.victims.length : x.n;
      return `<div class="ap-row${x.name === selected ? " selected" : ""}" data-name="${esc(x.name)}"><span class="nm">${esc(x.name)}</span><span class="dim">${n}</span></div>`;
    }).join("") : '<div class="ap-row"><span class="dim">Inga träffar</span></div>';
    listEl.querySelectorAll(".ap-row[data-name]").forEach(r => r.addEventListener("click", () => {
      selected = r.dataset.name; showProfile();
    }));
  }

  function setTab() {
    root.querySelectorAll("[data-tab]").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
    filterEl.value = "";
    renderList();
  }
  root.querySelectorAll("[data-tab]").forEach(b => b.addEventListener("click", () => {
    tab = b.dataset.tab; selected = null; setTab(); showProfile();
  }));
  filterEl.addEventListener("input", renderList);
  setTab();
})();
</script>
"""


def build_actor_profiles_block() -> str:
    """Returnerar HTML+JS för sektionen 'Aktörsprofiler'."""
    return _TEMPLATE
