"""
Dagsrapport — en tydlig sammanfattning per dag (UTC-dygn), som standard gårdagen.

Visar för vald dag (idag + 6 dagar bakåt, välj i rullistan):
  - nyckeltal
  - viktigaste rubrikerna (rangordnade: nordiska CERT, KEV, bevakningslista, AI-hot, teknikbevakning)
  - ransomware-offer (nordiska markerade)
  - nya aktivt utnyttjade sårbarheter (CISA KEV) och akuta CVE:er
  - träffar på bevakningslistan
  - nya IOC:er per källa och mest aktiva malware-familjer
  - alla artiklar per källa
och en knapp som laddar ner dagen som Markdown.

Helt deterministiskt, ingen LLM. Dygn = UTC (databasens tidsstämplar), vilket
kan skilja några timmar mot svensk tid.
"""

import html
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from storage import DB_PATH

try:
    from attack_mapping import parse_family_from_value
except Exception:  # pragma: no cover
    parse_family_from_value = None
try:
    from sector_watch import is_nordic_country
except Exception:  # pragma: no cover
    def is_nordic_country(c):
        return (c or "").upper() in {"SE", "NO", "DK", "FI", "IS"}
try:
    from tech_watch import _COMPILED as _TECH
except Exception:  # pragma: no cover
    _TECH = []
try:
    from ai_watch import _COMPILED as _AI
except Exception:  # pragma: no cover
    _AI = []

DAYS_BACK = 7
NORDIC_FEEDS = ("CERT-SE", "NSM NCSC", "DKCERT", "NCSC-FI", "NCSC-NL")
TOP_HEADLINES = 12
WEEKDAYS = ["måndag", "tisdag", "onsdag", "torsdag", "fredag", "lördag", "söndag"]

DIGEST_CSS = """
  .dg-bar { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; margin-bottom: 0.9rem; }
  .dg-bar select, .dg-bar button { background: var(--panel); color: var(--text); border: 1px solid var(--panel-border);
    border-radius: 6px; padding: 0.4rem 0.7rem; font-size: 0.85rem; cursor: pointer; font-family: inherit; }
  .dg-bar button:hover { border-color: var(--accent, #6ea8fe); }
  .dg-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.6rem; margin-bottom: 1rem; }
  .dg-kpi { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.6rem 0.8rem; }
  .dg-kpi b { display: block; font-size: 1.4rem; font-family: var(--mono, monospace); }
  .dg-kpi span { font-size: 0.75rem; color: var(--text-dim); }
  .dg-kpi.alert b { color: var(--red); }
  .dg-h { font-size: 0.78rem; margin: 1.1rem 0 0.4rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.04em; }
  .dg-day ul { margin: 0; padding-left: 1.1rem; font-size: 0.88rem; }
  .dg-day li { margin-bottom: 0.35rem; }
  .dg-tag { display: inline-block; font-size: 0.68rem; padding: 0.05rem 0.4rem; border-radius: 10px; margin-left: 0.3rem;
    border: 1px solid var(--panel-border); color: var(--text-dim); white-space: nowrap; }
  .dg-tag.red { color: var(--red); border-color: var(--red); }
  .dg-tag.amber { color: var(--amber); border-color: var(--amber); }
  .dg-day table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .dg-day td { padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); vertical-align: top; }
  .dg-day details { margin-top: 0.4rem; font-size: 0.85rem; }
  .dg-day summary { cursor: pointer; color: var(--text-dim); }
  .dg-empty { color: var(--text-dim); font-size: 0.88rem; }
"""


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _q(conn, query, params=()):
    try:
        cur = conn.execute(query, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def _tags_for(text: str) -> list:
    tags = []
    for name, rx in _TECH:
        if rx and rx.search(text):
            tags.append(("amber", name.split(" (")[0]))
    for _cid, name, _d, rx in _AI:
        if rx and rx.search(text):
            tags.append(("amber", "AI: " + name))
            break
    return tags[:3]


def _day_data(conn, day: str) -> dict:
    arts = _q(
        conn,
        """
        SELECT feed, title, link, summary, fetched_at FROM articles
        WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
          AND date(fetched_at) = ? ORDER BY id DESC
        """,
        (day,),
    )
    victims = _q(
        conn,
        "SELECT group_name, victim, country, sector FROM ransomware_victims WHERE date(first_seen) = ? ORDER BY id DESC",
        (day,),
    )
    watch = _q(
        conn,
        "SELECT entry, kind, detail, source, link FROM watchlist_hits WHERE date(first_seen) = ? ORDER BY id DESC",
        (day,),
    )
    ioc_rows = _q(
        conn,
        """
        SELECT articles.feed AS feed, iocs.value AS value FROM iocs
        JOIN articles ON articles.id = iocs.article_id
        WHERE date(articles.fetched_at) = ?
        """,
        (day,),
    )
    cves = _q(
        conn,
        "SELECT cve_id, cvss, epss, kev, summary FROM cve_enrichment "
        "WHERE date(checked_at) = ? AND (kev = 1 OR epss >= 0.5) ORDER BY kev DESC, epss DESC",
        (day,),
    )

    watch_text = " ".join(f"{w['entry']} {w['detail']}" for w in watch).lower()
    ranked = []
    for a in arts:
        text = f"{a['title']} {a['summary'] or ''}"
        score, tags = 0, []
        if any(a["feed"].startswith(n) for n in NORDIC_FEEDS):
            score += 3
            tags.append(("red", "Norden/CERT"))
        if a["feed"] == "CISA KEV":
            score += 3
            tags.append(("red", "KEV"))
        extra = _tags_for(text)
        score += 2 * len(extra)
        tags += extra
        if watch_text and any(w["entry"].lower() in text.lower() for w in watch):
            score += 3
            tags.append(("red", "bevakningslista"))
        ranked.append((score, a, tags))
    ranked.sort(key=lambda x: -x[0])

    by_feed_ioc, fam = {}, {}
    for r in ioc_rows:
        feed = r["feed"] or "okänd"
        by_feed_ioc[feed] = by_feed_ioc.get(feed, 0) + 1
        if parse_family_from_value and feed.startswith("ThreatFox"):
            f = parse_family_from_value(r["value"])
            if f:
                fam[f] = fam.get(f, 0) + 1

    return {
        "arts": arts, "ranked": ranked, "victims": victims, "watch": watch, "cves": cves,
        "kev_new": [a for a in arts if a["feed"] == "CISA KEV"],
        "ioc_total": len(ioc_rows),
        "ioc_by_feed": sorted(by_feed_ioc.items(), key=lambda x: -x[1]),
        "families": sorted(fam.items(), key=lambda x: -x[1])[:8],
    }


def _link(a) -> str:
    t = _esc(a["title"] or "(utan titel)")
    return f'<a href="{_esc(a["link"])}" target="_blank" rel="noopener">{t}</a>' if a.get("link") else t


def _render_day(day: str, d: dict) -> tuple:
    """Returnerar (html, markdown) för en dag."""
    nordic_v = [v for v in d["victims"] if is_nordic_country(v["country"])]
    kpis = [
        (len(d["arts"]), "nya artiklar", False),
        (d["ioc_total"], "nya IOC:er", False),
        (len(d["victims"]), "ransomware-offer", False),
        (len(nordic_v), "varav i Norden", bool(nordic_v)),
        (len(d["kev_new"]) + sum(1 for c in d["cves"] if c["kev"]), "KEV-sårbarheter", False),
        (len(d["watch"]), "träffar bevakningslista", bool(d["watch"])),
    ]
    h = ['<div class="dg-kpis">' + "".join(
        f'<div class="dg-kpi{" alert" if al else ""}"><b>{n}</b><span>{_esc(lbl)}</span></div>' for n, lbl, al in kpis
    ) + "</div>"]
    md = [f"# Dagsrapport {day}", "", "Nyckeltal: " + ", ".join(f"{n} {lbl}" for n, lbl, _ in kpis), ""]

    if not d["arts"] and not d["victims"] and not d["ioc_total"]:
        h.append('<p class="dg-empty">Ingen data insamlad denna dag (databasen sparar bara det agenten hunnit hämta).</p>')
        return "".join(h), "\n".join(md + ["Ingen data insamlad denna dag."])

    if d["watch"]:
        h.append('<div class="dg-h">Träffar på bevakningslistan</div><ul>' + "".join(
            f'<li><b>{_esc(w["entry"])}</b> <span class="dg-tag red">{_esc(w["kind"])}</span> {_esc(w["detail"])} '
            f'<span class="dim">{_esc(w["source"])}</span></li>' for w in d["watch"][:15]) + "</ul>")
        md += ["## Bevakningslista"] + [f"- **{w['entry']}** ({w['kind']}): {w['detail']}" for w in d["watch"][:15]] + [""]

    if d["ranked"]:
        top = d["ranked"][:TOP_HEADLINES]
        h.append('<div class="dg-h">Viktigaste rubrikerna</div><ul>' + "".join(
            f'<li>{_link(a)}'
            + "".join(f'<span class="dg-tag {c}">{_esc(t)}</span>' for c, t in tags)
            + f' <span class="dim">{_esc(a["feed"])}</span></li>' for _s, a, tags in top) + "</ul>")
        md += ["## Viktigaste rubrikerna"] + [
            f"- [{a['title']}]({a['link']}) ({a['feed']})" for _s, a, _t in top] + [""]

    if d["victims"]:
        ordered = sorted(d["victims"], key=lambda v: 0 if is_nordic_country(v["country"]) else 1)
        nordic_tag = '<span class="dg-tag red">Norden</span> '
        h.append(f'<div class="dg-h">Ransomware-offer ({len(d["victims"])})</div><table>' + "".join(
            "<tr><td>" + (nordic_tag if is_nordic_country(v["country"]) else "")
            + f'<b>{_esc(v["victim"])}</b></td><td>{_esc(v["country"] or "?")}</td>'
            f'<td>{_esc(v["sector"] or "")}</td><td class="dim">{_esc(v["group_name"])}</td></tr>'
            for v in ordered[:25]) + "</table>"
            + (f'<p class="dim">… och {len(d["victims"]) - 25} till.</p>' if len(d["victims"]) > 25 else ""))
        md += [f"## Ransomware-offer ({len(d['victims'])})"] + [
            f"- {v['victim']} ({v['country'] or '?'}, {v['group_name']})" + (" **[Norden]**" if is_nordic_country(v["country"]) else "")
            for v in ordered[:25]] + [""]

    if d["kev_new"] or d["cves"]:
        items = [f'<li>{_link(a)} <span class="dg-tag red">KEV</span></li>' for a in d["kev_new"][:10]]
        kev_tag = ' <span class="dg-tag red">KEV</span>'
        items += [
            f'<li class="mono">{_esc(c["cve_id"])}' + (kev_tag if c["kev"] else "")
            + (f' <span class="dim">EPSS {c["epss"]:.0%}</span>' if c["epss"] is not None else "")
            + f' <span class="dim" style="font-family:var(--sans)">{_esc((c["summary"] or "")[:110])}</span></li>'
            for c in d["cves"][:10]]
        h.append('<div class="dg-h">Sårbarheter (KEV / hög EPSS)</div><ul>' + "".join(items) + "</ul>")
        md += ["## Sårbarheter"] + [f"- {a['title']} (KEV)" for a in d["kev_new"][:10]] + [
            f"- {c['cve_id']}" + (" (KEV)" if c["kev"] else "") for c in d["cves"][:10]] + [""]

    if d["ioc_by_feed"]:
        fam = ", ".join(f"{_esc(f)} ({n})" for f, n in d["families"])
        h.append('<div class="dg-h">Nya IOC:er</div><p style="font-size:0.88rem;margin:0">'
                 + " · ".join(f"{_esc(f)}: <b>{n}</b>" for f, n in d["ioc_by_feed"][:8])
                 + (f'</p><p class="dim" style="font-size:0.85rem;margin:0.3rem 0 0">Mest aktiva familjer: {fam}.' if fam else "")
                 + "</p>")
        md += ["## Nya IOC:er"] + [f"- {f}: {n}" for f, n in d["ioc_by_feed"][:8]]
        if d["families"]:
            md += ["", "Mest aktiva familjer: " + ", ".join(f"{f} ({n})" for f, n in d["families"])]
        md += [""]

    if d["arts"]:
        groups = {}
        for a in d["arts"]:
            groups.setdefault(a["feed"], []).append(a)
        h.append(f'<details><summary>Alla {len(d["arts"])} artiklar per källa</summary>' + "".join(
            f'<div class="dg-h">{_esc(f)} ({len(items)})</div><ul>'
            + "".join(f"<li>{_link(a)}</li>" for a in items[:25]) + "</ul>"
            for f, items in sorted(groups.items())) + "</details>")

    return "".join(h), "\n".join(md)


_JS = """
(function () {
  var sel = document.getElementById('dgDay');
  if (!sel) return;
  var days = document.querySelectorAll('.dg-day');
  var md = __MD__;
  function show() {
    days.forEach(function (d) { d.style.display = d.dataset.day === sel.value ? '' : 'none'; });
  }
  sel.addEventListener('change', show);
  document.getElementById('dgMd').addEventListener('click', function () {
    var blob = new Blob([md[sel.value] || ''], { type: 'text/markdown;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'dagsrapport-' + sel.value + '.md';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });
  show();
})();
"""


def build_digest_block(db_path: str = DB_PATH) -> str:
    today = datetime.now(timezone.utc).date()
    conn = sqlite3.connect(db_path)
    options, bodies, md_by_day = [], [], {}
    for i in range(DAYS_BACK):
        day = today - timedelta(days=i)
        key = day.isoformat()
        label = {0: "Idag (pågår)", 1: "Igår"}.get(i, f"{WEEKDAYS[day.weekday()].capitalize()} {key}")
        if i in (0, 1):
            label += f" · {WEEKDAYS[day.weekday()]} {key}"
        h, md = _render_day(key, _day_data(conn, key))
        options.append(f'<option value="{key}"{" selected" if i == 1 else ""}>{_esc(label)}</option>')
        bodies.append(f'<div class="dg-day" data-day="{key}" style="display:none">{h}</div>')
        md_by_day[key] = md
    conn.close()

    data = json.dumps(md_by_day, ensure_ascii=False).replace("</", "<\\/")
    return (
        '<div class="dg-bar"><label for="dgDay" class="dim">Dag:</label>'
        f'<select id="dgDay">{"".join(options)}</select>'
        '<button id="dgMd" type="button">⬇ Ladda ner som Markdown</button>'
        '<span class="dim" style="font-size:0.78rem">Dygn räknas i UTC</span></div>'
        + "".join(bodies)
        + "<script>" + _JS.replace("__MD__", data) + "</script>"
    )
