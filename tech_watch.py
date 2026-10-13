"""
Teknikbevakning — matchar insamlad data mot produkterna i tech_watchlist.py.

Källor som matchas:
  - Nya aktivt utnyttjade sårbarheter (artiklar från "CISA KEV")
  - CVE-berikning (cve_enrichment: KEV/EPSS/CVSS + beskrivning)
  - Övriga artiklar (RSS/Telegram) senaste N dagarna

Helt deterministiskt nyckelordsmatchande — ingen LLM, inga nycklar.
Visas som sektionen 'Teknikbevakning' och ger även notis i agent.py när en
NY KEV-sårbarhet berör något på listan.
"""

import html
import re
import sqlite3

from storage import DB_PATH
from tech_watchlist import TECH_WATCHLIST

WINDOW_DAYS = 30
MAX_ARTICLES_SCANNED = 1500
KEV_FEED = "CISA KEV"


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _compile(keywords: list):
    parts = [r"(?<![a-z0-9])" + re.escape(k.lower()) + r"(?![a-z0-9])" for k in keywords if k.strip()]
    return re.compile("|".join(parts), re.I) if parts else None


_COMPILED = [(t["name"], _compile(t.get("keywords", []))) for t in TECH_WATCHLIST]


def match_kev_entries(entries: list) -> list:
    """
    entries: lista av dict med 'cve_id' och 'title' (från more_sources.run_kev).
    Returnerar [{'tech': namn, 'cve_id': ..., 'ransomware': bool}] för träffar.
    """
    hits = []
    for e in entries or []:
        text = f"{e.get('title', '')} {e.get('cve_id', '')}"
        for name, rx in _COMPILED:
            if rx and rx.search(text):
                hits.append({"tech": name, "cve_id": e.get("cve_id", ""), "ransomware": bool(e.get("ransomware"))})
    return hits


def _fetch(conn, query, params=()):
    try:
        cur = conn.execute(query, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def collect_tech_hits(db_path: str = DB_PATH, days: int = WINDOW_DAYS) -> list:
    """Returnerar en lista (sorterad efter 'hetta') med träffar per produkt."""
    conn = sqlite3.connect(db_path)
    cves = _fetch(
        conn,
        "SELECT cve_id, cvss, epss, kev, ransomware_campaign, summary FROM cve_enrichment "
        "ORDER BY kev DESC, epss DESC",
    )
    arts = _fetch(
        conn,
        """
        SELECT feed, title, link, summary, substr(full_text, 1, 2000) AS full_text, fetched_at
        FROM articles
        WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
          AND fetched_at >= datetime('now', ?)
        ORDER BY id DESC LIMIT ?
        """,
        (f"-{int(days)} day", MAX_ARTICLES_SCANNED),
    )
    conn.close()

    results = []
    for name, rx in _COMPILED:
        if not rx:
            continue
        cve_hits = [c for c in cves if rx.search(c["summary"] or "")]
        kev_new = [a for a in arts if a["feed"] == KEV_FEED and rx.search(f"{a['title']} {a['summary'] or ''}")]
        other = [
            a for a in arts
            if a["feed"] != KEV_FEED and rx.search(f"{a['title']} {a['summary'] or ''} {a['full_text'] or ''}")
        ]
        kev_cves = [c for c in cve_hits if c["kev"]]
        heat = len(kev_new) * 5 + len(kev_cves) * 2 + len(cve_hits) + len(other)
        results.append({
            "name": name, "cves": cve_hits, "kev_new": kev_new, "articles": other,
            "kev_cve_count": len(kev_cves), "heat": heat,
        })
    results.sort(key=lambda r: (-r["heat"], r["name"]))
    return results


TECH_CSS = """
  .tw-card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; margin-bottom: 0.6rem; }
  .tw-card > summary { cursor: pointer; padding: 0.7rem 1rem; display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
  .tw-card > summary::-webkit-details-marker { display: none; }
  .tw-name { font-weight: 600; margin-right: auto; }
  .tw-card.hot { border-left: 3px solid var(--red); }
  .tw-card.warm { border-left: 3px solid var(--amber); }
  .tw-body { padding: 0 1rem 0.9rem; font-size: 0.85rem; }
  .tw-body h4 { font-size: 0.78rem; margin: 0.9rem 0 0.35rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.04em; }
  .tw-body ul { margin: 0; padding-left: 1.1rem; }
  .tw-body li { margin-bottom: 0.25rem; }
  .tw-note { font-size: 0.78rem; margin-bottom: 0.8rem; white-space: normal; }
"""


def build_tech_watch_html(db_path: str = DB_PATH) -> str:
    results = collect_tech_hits(db_path)
    if not results:
        return '<p class="empty">Ingen teknikbevakning konfigurerad (se tech_watchlist.py).</p>'

    cards = []
    for r in results:
        cls = "hot" if r["kev_new"] else ("warm" if (r["kev_cve_count"] or r["cves"] or r["articles"]) else "")
        badges = []
        if r["kev_new"]:
            badges.append(f'<span class="badge badge-critical">{len(r["kev_new"])} ny KEV</span>')
        if r["kev_cve_count"]:
            badges.append(f'<span class="badge badge-high">{r["kev_cve_count"]} KEV-CVE</span>')
        if r["cves"]:
            badges.append(f'<span class="dim">{len(r["cves"])} CVE</span>')
        if r["articles"]:
            badges.append(f'<span class="dim">{len(r["articles"])} artiklar</span>')
        if not badges:
            badges.append('<span class="dim">inga träffar</span>')

        body = []
        if r["kev_new"]:
            body.append("<h4>Nya aktivt utnyttjade sårbarheter (CISA KEV)</h4><ul>" + "".join(
                f'<li><a href="{_esc(a["link"])}" target="_blank" rel="noopener">{_esc(a["title"])}</a>'
                f'<div class="dim" style="white-space:normal">{_esc((a["summary"] or "")[:220])}</div></li>'
                for a in r["kev_new"][:10]) + "</ul>")
        if r["cves"]:
            def _cve_li(c):
                flag = '<span class="badge badge-critical">KEV</span> ' if c["kev"] else ""
                epss = f' <span class="dim">EPSS {c["epss"]:.0%}</span>' if c["epss"] is not None else ""
                return (f'<li class="mono">{flag}{_esc(c["cve_id"])}{epss} '
                        f'<span class="dim" style="font-family:var(--sans)">{_esc((c["summary"] or "")[:130])}</span></li>')
            body.append("<h4>CVE:er (KEV/EPSS-prioriterade)</h4><ul>" + "".join(_cve_li(c) for c in r["cves"][:10]) + "</ul>")
        if r["articles"]:
            body.append("<h4>Artiklar som nämner produkten</h4><ul>" + "".join(
                f'<li><a href="{_esc(a["link"])}" target="_blank" rel="noopener">{_esc(a["title"])}</a> '
                f'<span class="dim">{_esc(a["feed"])}</span></li>' for a in r["articles"][:10]) + "</ul>")
        if not body:
            body.append(f'<p class="dim">Inga träffar de senaste {WINDOW_DAYS} dagarna.</p>')

        cards.append(
            f'<details class="tw-card {cls}"{" open" if cls == "hot" else ""}>'
            f'<summary><span class="tw-name">{_esc(r["name"])}</span>{"".join(badges)}</summary>'
            f'<div class="tw-body">{"".join(body)}</div></details>'
        )

    note = (f'<p class="dim tw-note">Matchar CISA KEV, CVE-data och artiklar (senaste {WINDOW_DAYS} dagarna) mot '
            f'produkterna i <code>tech_watchlist.py</code>. Nyckelordsmatchning – kontrollera alltid att träffen '
            f'gäller just din version/konfiguration.</p>')
    return note + "".join(cards)
