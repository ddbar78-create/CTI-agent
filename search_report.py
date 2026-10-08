"""
Sök & rapport — fritextsökning över allt agenten samlat in, direkt i
dashboarden (index.html). Ingen server behövs: datat bäddas in som JSON och
sökningen körs i webbläsaren.

Sök t.ex. på: ett malware-namn (Vidar), en hotaktör/ransomware-grupp (qilin),
en CVE (CVE-2026-1234), en domän, ett IP, en hash, ett land (SE) eller en
teknik (T1566, phishing). Flera ord = alla måste matcha.

Knappen "Skapa rapport" bygger en rapport över träffarna (sammanfattning,
malware/ATT&CK, IOCs, artiklar, offer, CVE:er) samt färdiga hunting-frågor
(Microsoft Defender KQL och Splunk) som laddas ner som Markdown eller HTML.
"""

import json
import re
import sqlite3

from storage import DB_PATH

try:
    from attack_mapping import parse_family_from_value, classify_family
except Exception:  # pragma: no cover - modulen ska finnas, men tappa inte hela dashboarden
    parse_family_from_value = None
    classify_family = None

MAX_ARTICLES = 600
MAX_IOCS = 8000
MAX_VICTIMS = 3000
TEXT_CHARS = 1200

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _clean_text(text) -> str:
    if not text:
        return ""
    text = _TAG_RE.sub(" ", str(text))
    return _WS_RE.sub(" ", text).strip()[:TEXT_CHARS]


def _norm_technique(t) -> str:
    if isinstance(t, str):
        return t
    if isinstance(t, dict):
        return " ".join(str(v) for v in t.values())
    if isinstance(t, (list, tuple)):
        return " ".join(str(v) for v in t)
    return str(t)


def _fetch(conn, query, params=()):
    try:
        return conn.execute(query, params).fetchall()
    except sqlite3.Error:
        return []


def build_search_data(db_path: str = DB_PATH) -> dict:
    conn = sqlite3.connect(db_path)

    articles = [
        [r[0] or "", r[1] or "", r[2] or "", (r[3] or "")[:25], _clean_text(r[4] or r[5])]
        for r in _fetch(
            conn,
            """
            SELECT title, link, feed, published, full_text, summary FROM articles
            WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
            ORDER BY id DESC LIMIT ?
            """,
            (MAX_ARTICLES,),
        )
    ]

    iocs = [
        [r[0], r[1], r[2] or ""]
        for r in _fetch(
            conn,
            """
            SELECT iocs.ioc_type, iocs.value, articles.feed FROM iocs
            JOIN articles ON articles.id = iocs.article_id
            ORDER BY iocs.id DESC LIMIT ?
            """,
            (MAX_IOCS,),
        )
    ]

    victims = [
        [r[0] or "", r[1] or "", r[2] or "", r[3] or "", r[4] or ""]
        for r in _fetch(
            conn,
            """
            SELECT group_name, victim, country, sector, attack_date
            FROM ransomware_victims ORDER BY id DESC LIMIT ?
            """,
            (MAX_VICTIMS,),
        )
    ]

    cves = [
        [r[0], r[1], r[2], int(r[3] or 0), (r[4] or "")[:300], r[5] or ""]
        for r in _fetch(
            conn,
            """
            SELECT cve_id, cvss, epss, kev, summary, ransomware_campaign
            FROM cve_enrichment ORDER BY kev DESC, epss DESC
            """,
        )
    ]
    conn.close()

    # Malware-familjer funna i IOC-värdena -> ATT&CK-kategori + tekniker
    families = {}
    if parse_family_from_value and classify_family:
        for _type, value, _feed in iocs:
            fam = parse_family_from_value(value)
            if fam and fam not in families:
                try:
                    category, techniques = classify_family(fam)
                except Exception:
                    category, techniques = "", []
                families[fam] = {
                    "cat": str(category or ""),
                    "tech": [_norm_technique(t) for t in (techniques or [])],
                }

    return {
        "articles": articles, "iocs": iocs, "victims": victims,
        "cves": cves, "families": families,
    }


_TEMPLATE = r"""
<div class="sr-wrap">
  <div class="sr-bar">
    <input type="search" id="srInput" class="sr-input" autocomplete="off"
           placeholder="Sök: malware, aktör/grupp, CVE, domän, IP, hash, land, teknik (t.ex. T1566)…">
    <button class="map-btn" id="srReport" disabled>📄 Skapa rapport</button>
  </div>
  <div class="sr-examples dim">
    Exempel:
    <a href="#" class="sr-ex">qilin</a> ·
    <a href="#" class="sr-ex">vidar</a> ·
    <a href="#" class="sr-ex">phishing</a> ·
    <a href="#" class="sr-ex">T1566</a> ·
    <a href="#" class="sr-ex">CVE-2026</a> ·
    <a href="#" class="sr-ex">SE</a>
  </div>
  <div id="srSummary" class="sr-summary"></div>
  <div id="srResults"></div>
</div>
<script>
(function() {
  const D = __DATA__;
  const input = document.getElementById("srInput");
  const reportBtn = document.getElementById("srReport");
  const summaryEl = document.getElementById("srSummary");
  const resultsEl = document.getElementById("srResults");
  const PAGE = 25;
  let current = null;
  const shown = {};

  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const cleanValue = v => String(v).split(" [")[0].trim();
  const familyOf = v => { const m = String(v).match(/\[([^\],]+),/); return m ? m[1].trim() : ""; };

  const hay = {
    articles: D.articles.map(a => (a[0] + " " + a[2] + " " + a[4]).toLowerCase()),
    iocs: D.iocs.map(i => (i[0] + " " + i[1] + " " + i[2]).toLowerCase()),
    victims: D.victims.map(v => v.join(" ").toLowerCase()),
    cves: D.cves.map(c => (c[0] + " " + c[4] + " " + c[5]).toLowerCase()),
  };
  const famNames = Object.keys(D.families);
  const famHay = famNames.map(n => (n + " " + D.families[n].cat + " " + D.families[n].tech.join(" ")).toLowerCase());

  function matchAll(h, terms) { return terms.every(t => h.includes(t)); }

  function search(q) {
    const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    const r = { q, articles: [], iocs: [], victims: [], cves: [], families: [] };
    D.articles.forEach((a, i) => { if (matchAll(hay.articles[i], terms)) r.articles.push(a); });
    D.iocs.forEach((x, i) => { if (matchAll(hay.iocs[i], terms)) r.iocs.push(x); });
    D.victims.forEach((v, i) => { if (matchAll(hay.victims[i], terms)) r.victims.push(v); });
    D.cves.forEach((c, i) => { if (matchAll(hay.cves[i], terms)) r.cves.push(c); });
    // familjer: antingen namn/kategori/teknik matchar, eller familjen finns bland träffade IOCs
    const fromIocs = {};
    r.iocs.forEach(x => { const f = familyOf(x[1]); if (f) fromIocs[f] = (fromIocs[f] || 0) + 1; });
    const famSet = new Set();
    famNames.forEach((n, i) => { if (matchAll(famHay[i], terms)) famSet.add(n); });
    Object.keys(fromIocs).forEach(n => famSet.add(n));
    r.families = Array.from(famSet).map(n => ({
      name: n, cat: (D.families[n] || {}).cat || "", tech: (D.families[n] || {}).tech || [],
      iocCount: fromIocs[n] || 0
    })).sort((a, b) => b.iocCount - a.iocCount);
    return r;
  }

  const techLink = t => {
    const m = String(t).match(/T\d{4}(?:\.\d{3})?/);
    return m ? `<a href="https://attack.mitre.org/techniques/${m[0].replace(".", "/")}/" target="_blank" rel="noopener">${esc(t)}</a>` : esc(t);
  };

  function block(key, title, items, rowFn) {
    if (!items.length) return "";
    const n = shown[key] || PAGE;
    const rows = items.slice(0, n).map(rowFn).join("");
    const more = items.length > n
      ? `<button class="map-btn sr-more" data-key="${key}">Visa fler (${items.length - n} kvar)</button>` : "";
    return `<div class="sr-block"><h3>${title} <span class="dim">(${items.length})</span></h3>
      <table><tbody>${rows}</tbody></table>${more}</div>`;
  }

  function render() {
    if (!current) { summaryEl.innerHTML = ""; resultsEl.innerHTML = ""; reportBtn.disabled = true; return; }
    const r = current;
    const total = r.articles.length + r.iocs.length + r.victims.length + r.cves.length + r.families.length;
    reportBtn.disabled = total === 0;
    if (!total) {
      summaryEl.innerHTML = `<span class="dim">Inga träffar för <strong>${esc(r.q)}</strong>.</span>`;
      resultsEl.innerHTML = ""; return;
    }
    summaryEl.innerHTML = `Träffar för <strong>${esc(r.q)}</strong>: ` +
      `<span class="sr-chip">${r.families.length} malware</span>` +
      `<span class="sr-chip">${r.iocs.length} IOCs</span>` +
      `<span class="sr-chip">${r.articles.length} artiklar</span>` +
      `<span class="sr-chip">${r.victims.length} offer</span>` +
      `<span class="sr-chip">${r.cves.length} CVE</span>` +
      (D.iocs.length >= __MAXIOCS__ ? `<div class="dim" style="margin-top:.3rem">Obs: sökningen täcker de senaste ${D.iocs.length} IOC:erna.</div>` : "");

    let h = "";
    h += block("families", "Malware &amp; ATT&amp;CK", r.families, f =>
      `<tr><td><strong>${esc(f.name)}</strong></td><td class="dim">${esc(f.cat)}</td>
        <td>${f.tech.map(techLink).join(", ") || '<span class="dim">—</span>'}</td>
        <td class="dim">${f.iocCount ? f.iocCount + " IOCs" : ""}</td></tr>`);
    h += block("victims", "Ransomware-offer", r.victims, v =>
      `<tr><td><strong>${esc(v[0])}</strong></td><td>${esc(v[1])}</td><td class="dim">${esc(v[2])}</td><td class="dim">${esc(v[3])}</td><td class="dim">${esc(v[4])}</td></tr>`);
    h += block("cves", "CVE:er", r.cves, c =>
      `<tr><td class="mono">${esc(c[0])}</td><td>${c[3] ? '<span class="badge badge-critical">KEV</span>' : ""}</td>
        <td class="dim">${c[2] != null ? "EPSS " + Math.round(c[2] * 100) + "%" : ""}${c[1] ? " · CVSS " + esc(c[1]) : ""}</td>
        <td class="dim">${esc(c[4])}</td></tr>`);
    h += block("iocs", "IOCs", r.iocs, x =>
      `<tr><td class="mono dim">${esc(x[0])}</td><td class="mono ioc-value">${esc(x[1])}</td><td class="dim">${esc(x[2])}</td></tr>`);
    h += block("articles", "Artiklar", r.articles, a =>
      `<tr><td class="dim">${esc(a[2])}</td><td><a href="${esc(a[1])}" target="_blank" rel="noopener">${esc(a[0])}</a>
        <div class="dim sr-snippet">${esc(a[4].slice(0, 220))}</div></td></tr>`);
    resultsEl.innerHTML = h;
    resultsEl.querySelectorAll(".sr-more").forEach(b => b.addEventListener("click", () => {
      shown[b.dataset.key] = (shown[b.dataset.key] || PAGE) + 50; render();
    }));
  }

  let timer = null;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const q = input.value.trim();
      Object.keys(shown).forEach(k => delete shown[k]);
      current = q.length >= 2 ? search(q) : null;
      render();
    }, 200);
  });
  document.querySelectorAll(".sr-ex").forEach(a => a.addEventListener("click", e => {
    e.preventDefault(); input.value = a.textContent; input.dispatchEvent(new Event("input"));
  }));

  // ---------- Rapport ----------
  const defang = (type, v) => {
    if (["domain", "url", "ipv4", "ip:port"].includes(type)) {
      return v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
    }
    return v;
  };
  const q = a => a.map(v => '"' + v.replace(/"/g, '\\"') + '"').join(", ");

  function buildHunting(r) {
    const by = {};
    r.iocs.forEach(x => { (by[x[0]] = by[x[0]] || new Set()).add(cleanValue(x[1])); });
    const arr = t => Array.from(by[t] || []).slice(0, 100);
    const sha256 = arr("sha256_hash"), sha1 = arr("sha1_hash"), md5 = arr("md5_hash");
    const domains = arr("domain"), urls = arr("url");
    const ips = Array.from(new Set([...arr("ipv4"), ...arr("ip:port")].map(v => v.split(":")[0]))).slice(0, 100);
    const out = [];
    if (sha256.length || sha1.length || md5.length) {
      out.push("### Microsoft Defender (KQL) – filer\n```kql\nDeviceFileEvents\n| where Timestamp > ago(30d)\n| where " +
        [sha256.length ? "SHA256 in~ (" + q(sha256) + ")" : "", sha1.length ? "SHA1 in~ (" + q(sha1) + ")" : "", md5.length ? "MD5 in~ (" + q(md5) + ")" : ""]
          .filter(Boolean).join("\n    or ") +
        "\n| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName\n```");
    }
    if (domains.length || urls.length || ips.length) {
      out.push("### Microsoft Defender (KQL) – nätverk\n```kql\nDeviceNetworkEvents\n| where Timestamp > ago(30d)\n| where " +
        [domains.length ? "RemoteUrl has_any (" + q(domains) + ")" : "", urls.length ? "RemoteUrl has_any (" + q(urls) + ")" : "", ips.length ? "RemoteIP in (" + q(ips) + ")" : ""]
          .filter(Boolean).join("\n    or ") +
        "\n| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName\n```");
    }
    const all = [...sha256, ...sha1, ...md5, ...domains, ...ips].slice(0, 100);
    if (all.length) {
      out.push("### Splunk (generisk)\n```spl\nindex=* earliest=-30d (" + all.map(v => '"' + v + '"').join(" OR ") + ")\n| stats count min(_time) as first max(_time) as last by host, source, sourcetype\n```");
    }
    return out.join("\n\n");
  }

  function buildMarkdown(r, doDefang) {
    const now = new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC";
    const L = [];
    L.push(`# Hotunderrättelserapport: ${r.q}`, "", `Genererad ${now} från CTI-agentens insamlade data. Automatisk sammanställning – verifiera mot primärkällor innan åtgärd.`, "");
    L.push("## Sammanfattning", "",
      `- Malware-familjer: **${r.families.length}**`, `- IOCs: **${r.iocs.length}**`,
      `- Artiklar: **${r.articles.length}**`, `- Ransomware-offer: **${r.victims.length}**`, `- CVE:er: **${r.cves.length}**`, "");
    if (r.families.length) {
      L.push("## Malware, TTP:er och ATT&CK", "", "| Familj | Kategori | Tekniker | IOCs |", "|---|---|---|---|");
      r.families.slice(0, 50).forEach(f => L.push(`| ${f.name} | ${f.cat} | ${f.tech.join("; ") || "—"} | ${f.iocCount || ""} |`));
      L.push("", "_ATT&CK-mappningen är kategoribaserad approximation, inte bekräftad per incident._", "");
    }
    if (r.cves.length) {
      L.push("## CVE:er", "");
      r.cves.slice(0, 50).forEach(c => L.push(`- **${c[0]}**${c[3] ? " (KEV – aktivt utnyttjad)" : ""}${c[2] != null ? ", EPSS " + Math.round(c[2] * 100) + "%" : ""}${c[1] ? ", CVSS " + c[1] : ""} – ${c[4]}`));
      L.push("");
    }
    if (r.victims.length) {
      L.push("## Ransomware-offer", "");
      r.victims.slice(0, 100).forEach(v => L.push(`- ${v[0]} → ${v[1]} (${v[2]}${v[3] ? ", " + v[3] : ""}${v[4] ? ", " + v[4] : ""})`));
      if (r.victims.length > 100) L.push(`- … och ${r.victims.length - 100} till`);
      L.push("");
    }
    if (r.iocs.length) {
      const grouped = {};
      r.iocs.slice(0, 500).forEach(x => { (grouped[x[0]] = grouped[x[0]] || []).push(x); });
      L.push("## Indikatorer (IOCs)", "", doDefang ? "_Defangade (hxxp, [.]) för säker hantering._" : "_Obs: odefangade – hantera försiktigt._", "");
      Object.keys(grouped).forEach(t => {
        L.push(`### ${t} (${grouped[t].length})`, "```");
        grouped[t].forEach(x => L.push(doDefang ? defang(x[0], x[1]) : x[1]));
        L.push("```", "");
      });
      if (r.iocs.length > 500) L.push(`_Visar 500 av ${r.iocs.length} IOCs._`, "");
    }
    const hunt = buildHunting(r);
    if (hunt) L.push("## Förslag på threat hunting", "", "Mallfrågor byggda från IOC:erna ovan (odefangade, max 100 värden/typ). Anpassa tabeller/fält efter din miljö.", "", hunt, "");
    if (r.articles.length) {
      L.push("## Källor och artiklar", "");
      r.articles.slice(0, 50).forEach(a => L.push(`- [${a[0]}](${a[1]}) – ${a[2]}`));
      L.push("");
    }
    return L.join("\n");
  }

  function mdToHtml(md) {
    // enkel, säker konvertering av just de konstruktioner rapporten använder
    const lines = md.split("\n"); const out = []; let inCode = false, inTable = false, inList = false;
    const inline = s => esc(s).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/_(.+?)_/g, "<em>$1</em>")
      .replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$2">$1</a>');
    const closeBlocks = () => { if (inTable) { out.push("</table>"); inTable = false; } if (inList) { out.push("</ul>"); inList = false; } };
    lines.forEach(l => {
      if (l.startsWith("```")) { closeBlocks(); out.push(inCode ? "</pre>" : "<pre>"); inCode = !inCode; return; }
      if (inCode) { out.push(esc(l)); return; }
      if (/^\|[-| ]+\|$/.test(l)) return;
      if (l.startsWith("|")) {
        if (!inTable) { closeBlocks(); out.push("<table>"); inTable = true; }
        const cells = l.split("|").slice(1, -1).map(c => "<td>" + inline(c.trim()) + "</td>").join("");
        out.push("<tr>" + cells + "</tr>"); return;
      }
      if (l.startsWith("- ")) { if (!inList) { closeBlocks(); out.push("<ul>"); inList = true; } out.push("<li>" + inline(l.slice(2)) + "</li>"); return; }
      closeBlocks();
      const m = l.match(/^(#{1,3}) (.*)$/);
      if (m) out.push(`<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`);
      else if (l.trim()) out.push("<p>" + inline(l) + "</p>");
    });
    closeBlocks();
    return out.join("\n");
  }

  function download(name, text, type) {
    const blob = new Blob([text], { type: type + ";charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  reportBtn.addEventListener("click", () => {
    if (!current) return;
    const doDefang = confirm("Defanga domäner/URL:er/IP i rapporten (hxxp, [.])?\n\nOK = ja (säkrare att dela), Avbryt = nej");
    const fmt = confirm("Ladda ner som HTML (kan skrivas ut/sparas som PDF)?\n\nOK = HTML, Avbryt = Markdown");
    const md = buildMarkdown(current, doDefang);
    const slug = current.q.toLowerCase().replace(/[^a-z0-9åäö]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "sokning";
    if (fmt) {
      const doc = "<!doctype html><html lang='sv'><meta charset='utf-8'><title>Rapport: " + esc(current.q) + "</title>" +
        "<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1f29;line-height:1.5}" +
        "table{border-collapse:collapse;width:100%;font-size:.88rem}td{border-bottom:1px solid #ddd;padding:.3rem .5rem;vertical-align:top}" +
        "pre{background:#f3f4f6;padding:.8rem;overflow:auto;font-size:.8rem;white-space:pre-wrap;word-break:break-all}" +
        "h1{border-bottom:2px solid #333}h2{margin-top:2rem;border-bottom:1px solid #ccc}</style><body>" + mdToHtml(md) + "</body></html>";
      download("rapport-" + slug + ".html", doc, "text/html");
    } else {
      download("rapport-" + slug + ".md", md, "text/markdown");
    }
  });
})();
</script>
"""

SEARCH_CSS = """
  .sr-wrap { font-size: 0.88rem; }
  .sr-bar { display: flex; gap: 0.6rem; margin-bottom: 0.5rem; }
  .sr-input {
    flex: 1; background: var(--panel); border: 1px solid var(--panel-border); color: var(--text);
    padding: 0.6rem 0.9rem; border-radius: 6px; font-size: 0.95rem; font-family: var(--sans);
  }
  .sr-input:focus { outline: none; border-color: var(--amber); }
  .map-btn:disabled { opacity: 0.4; cursor: default; }
  .sr-examples { font-size: 0.78rem; margin-bottom: 0.8rem; white-space: normal; }
  .sr-summary { margin: 0.6rem 0 1rem; }
  .sr-chip {
    display: inline-block; background: var(--panel); border: 1px solid var(--panel-border);
    border-radius: 12px; padding: 0.1rem 0.6rem; margin-left: 0.4rem; font-size: 0.78rem;
  }
  .sr-block { margin-bottom: 1.4rem; }
  .sr-block h3 { font-size: 0.85rem; margin: 0 0 0.4rem; }
  .sr-snippet { white-space: normal; margin-top: 0.15rem; }
  .sr-more { margin-top: 0.5rem; }
"""


def build_search_block(db_path: str = DB_PATH) -> str:
    """Returnerar färdig HTML+JS för sektionen 'Sök & rapport'."""
    data = build_search_data(db_path)
    data_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return _TEMPLATE.replace("__DATA__", data_json).replace("__MAXIOCS__", str(MAX_IOCS))
