"""
IOC-förtroende och åldrande — ger varje indikator en poäng 0-100 och en status.

Poängen bygger på:
  + källans basförtroende (kurerade källor som ThreatFox, URLhaus, Feodo och MalwareBazaar högre än
    värden som bara plockats ur artikeltext), eller ThreatFox eget confidence-värde om det finns
  + 10 per extra oberoende källa (max 20) och 5 om indikatorn kopplats till en känd familj
  - åldersavdrag som beror på typ: IP och URL förfaller snabbt, domäner långsammare, hashar långsammast
  - 40 för värden som är olämpliga att blockera (privata adresser, vanliga nyhets- och molnsajter)

Status: aktiv (färsk), avtagande (äldre än halva livslängden), inaktuell (äldre än livslängden).
Blocklistor och STIX-exporten tar bara med aktiva och avtagande indikatorer med poäng 70 eller mer.

Resultatet sparas i tabellen ioc_scores (byggs om vid varje körning).
"""

import html
import ipaddress
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone

from storage import DB_PATH

MIN_BLOCK_SCORE = 70
MAX_ROWS = 300000

try:
    from attack_mapping import parse_family_from_value
except Exception:  # pragma: no cover
    parse_family_from_value = None

# Livslängd i dagar per IOC-typ
LIFETIME = {
    "ipv4": 30, "ip:port": 30, "url": 14, "domain": 60,
    "sha256_hash": 180, "sha1_hash": 180, "md5_hash": 180,
}
DEFAULT_LIFETIME = 90

CURATED = ("threatfox", "urlhaus", "feodo", "malwarebazaar", "mbazaar", "openphish")
SEMI = ("otx", "alienvault")
# Vanliga sajter som ofta nämns i artiklar men aldrig bör blockeras
BENIGN_DOMAINS = {
    "github.com", "google.com", "youtube.com", "twitter.com", "x.com", "facebook.com", "linkedin.com",
    "microsoft.com", "windows.com", "apple.com", "cisco.com", "virustotal.com", "mitre.org", "cloudflare.com",
    "amazonaws.com", "wikipedia.org", "bleepingcomputer.com", "thehackernews.com", "securelist.com",
    "reddit.com", "medium.com", "t.me", "telegram.org", "mozilla.org", "cisa.gov", "nist.gov",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_scores (
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    score INTEGER NOT NULL,
    status TEXT NOT NULL,
    sources INTEGER NOT NULL DEFAULT 1,
    family TEXT,
    first_seen TEXT,
    last_seen TEXT,
    PRIMARY KEY (ioc_type, value)
)
"""


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def _clean(value: str) -> str:
    return str(value).split(" [")[0].strip()


def _confidence(value: str):
    import re
    m = re.search(r"confidence\s+(\d+)", str(value), re.I)
    return int(m.group(1)) if m else None


def _family(value: str) -> str:
    if parse_family_from_value:
        try:
            return parse_family_from_value(str(value)) or ""
        except Exception:
            return ""
    import re
    m = re.search(r"\[([^\],]+),", str(value))
    return m.group(1).strip() if m else ""


def _base(feed: str, conf):
    low = (feed or "").lower()
    if any(k in low for k in CURATED):
        return conf if conf is not None else 75
    if any(k in low for k in SEMI):
        return 55
    return 30


def _low_value(ioc_type: str, clean: str) -> bool:
    if ioc_type in ("ipv4", "ip:port"):
        try:
            return not ipaddress.ip_address(clean.split(":")[0]).is_global
        except ValueError:
            return True
    if ioc_type == "domain":
        d = clean.lower().strip(".")
        return d in BENIGN_DOMAINS or any(d.endswith("." + b) for b in BENIGN_DOMAINS)
    return False


def _day(s: str):
    try:
        return datetime.strptime((s or "")[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def score_ioc(ioc_type, clean, feeds, confs, family, last_seen, today=None):
    """Returnerar (poäng, status). feeds = mängd av källnamn, confs = lista med confidence-värden."""
    today = today or datetime.now(timezone.utc).date()
    base = max((_base(f, max(confs) if confs else None) for f in feeds), default=30)
    score = base + min(20, 10 * (len(feeds) - 1)) + (5 if family else 0)
    life = LIFETIME.get(ioc_type, DEFAULT_LIFETIME)
    age = (today - last_seen).days if last_seen else life
    if age <= 0.5 * life:
        status = "aktiv"
    elif age <= life:
        status = "avtagande"
        score -= 25 * (age - 0.5 * life) / (0.5 * life)
    else:
        status = "inaktuell"
        score -= 25 + min(35, (age - life) / life * 35)
    if _low_value(ioc_type, clean):
        score -= 40
    return max(0, min(100, round(score))), status


def run_ioc_scores(db_path: str = DB_PATH) -> int:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT iocs.ioc_type, iocs.value, articles.feed, COALESCE(articles.fetched_at, '')
            FROM iocs JOIN articles ON articles.id = iocs.article_id
            WHERE iocs.ioc_type != 'cve' ORDER BY iocs.id DESC LIMIT ?
            """,
            (MAX_ROWS,),
        ).fetchall()
    except sqlite3.Error:
        rows = []
    agg = {}
    for ioc_type, value, feed, fetched in rows:
        clean = _clean(value)
        if not clean:
            continue
        key = (ioc_type, clean.lower())
        a = agg.get(key)
        if a is None:
            a = agg[key] = {"clean": clean, "feeds": set(), "confs": [], "family": "", "first": None, "last": None}
        a["feeds"].add(feed or "")
        c = _confidence(value)
        if c is not None:
            a["confs"].append(c)
        a["family"] = a["family"] or _family(value)
        d = _day(fetched)
        if d:
            a["first"] = min(a["first"], d) if a["first"] else d
            a["last"] = max(a["last"], d) if a["last"] else d

    out = []
    for (ioc_type, _k), a in agg.items():
        score, status = score_ioc(ioc_type, a["clean"], a["feeds"], a["confs"], a["family"], a["last"])
        out.append((ioc_type, a["clean"], score, status, len(a["feeds"]), a["family"],
                    a["first"].isoformat() if a["first"] else "", a["last"].isoformat() if a["last"] else ""))
    conn.execute("DELETE FROM ioc_scores")
    conn.executemany(
        "INSERT OR REPLACE INTO ioc_scores (ioc_type, value, score, status, sources, family, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", out)
    conn.commit()
    conn.close()
    print(f"[+] IOC-förtroende: {len(out)} indikatorer poängsatta.")
    return len(out)


def load_scores(db_path: str = DB_PATH) -> dict:
    """{(typ, värde i gemener): (poäng, status)} — tom om tabellen saknas."""
    try:
        conn = sqlite3.connect(db_path)
        data = {(t, v.lower()): (s, st) for t, v, s, st in conn.execute("SELECT ioc_type, value, score, status FROM ioc_scores")}
        conn.close()
        return data
    except sqlite3.Error:
        return {}


def active_iocs(db_path: str = DB_PATH, min_score: int = MIN_BLOCK_SCORE, types=None, limit: int = 500) -> list:
    """Aktiva eller avtagande indikatorer, högst poäng först. Returnerar dicts."""
    try:
        conn = sqlite3.connect(db_path)
        q = ("SELECT ioc_type, value, score, status, sources, family, last_seen FROM ioc_scores "
             "WHERE score >= ? AND status != 'inaktuell'")
        params = [min_score]
        if types:
            q += " AND ioc_type IN (%s)" % ",".join("?" * len(types))
            params += list(types)
        q += " ORDER BY score DESC, last_seen DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    return [dict(zip(("type", "value", "score", "status", "sources", "family", "last"), r)) for r in rows]


# ---------------------------------------------------------------- visning
IOC_CONF_CSS = """
  .ic-sum { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.5rem; margin-bottom: 0.9rem; }
  .ic-sum div { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.5rem 0.7rem; }
  .ic-sum b { display: block; font-size: 1.2rem; font-family: var(--mono, monospace); }
  .ic-sum span { font-size: 0.72rem; color: var(--text-dim); }
  .ic-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
  .ic-table th { text-align: left; font-weight: 500; color: var(--text-dim); font-size: 0.74rem; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .ic-table td { padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .ic-table td.v { font-family: var(--mono, monospace); word-break: break-all; }
  .ic-st-aktiv { color: var(--green, #3fb950); } .ic-st-avtagande { color: var(--amber); } .ic-st-inaktuell { color: var(--text-dim); }
"""


def build_ioc_confidence_html(db_path: str = DB_PATH) -> str:
    try:
        conn = sqlite3.connect(db_path)
        total = conn.execute("SELECT COUNT(*) FROM ioc_scores").fetchone()[0]
        by_status = dict(conn.execute("SELECT status, COUNT(*) FROM ioc_scores GROUP BY status"))
        blockable = conn.execute(
            "SELECT COUNT(*) FROM ioc_scores WHERE score >= ? AND status != 'inaktuell'", (MIN_BLOCK_SCORE,)).fetchone()[0]
        conn.close()
    except sqlite3.Error:
        total = 0
    if not total:
        return '<p class="empty">Inga poängsatta indikatorer ännu, fylls vid nästa körning.</p>'
    top = active_iocs(db_path, min_score=0, limit=40)
    rows = "".join(
        f'<tr><td>{html.escape(r["type"])}</td><td class="v">{html.escape(r["value"][:90])}</td>'
        f'<td><b>{r["score"]}</b></td><td class="ic-st-{r["status"]}">{r["status"]}</td>'
        f'<td>{r["sources"]}</td><td>{html.escape(r["family"] or "–")}</td><td>{html.escape(r["last"] or "")}</td></tr>'
        for r in top
    )
    return (
        '<div class="ic-sum">'
        f'<div><b>{total}</b><span>indikatorer</span></div>'
        f'<div><b>{by_status.get("aktiv", 0)}</b><span>aktiva</span></div>'
        f'<div><b>{by_status.get("avtagande", 0)}</b><span>avtagande</span></div>'
        f'<div><b>{by_status.get("inaktuell", 0)}</b><span>inaktuella</span></div>'
        f'<div><b>{blockable}</b><span>i blocklistorna (poäng ≥ {MIN_BLOCK_SCORE})</span></div></div>'
        '<table class="ic-table"><tr><th>Typ</th><th>Värde</th><th>Poäng</th><th>Status</th><th>Källor</th><th>Familj</th><th>Senast sedd</th></tr>'
        + rows + "</table>"
        '<p class="dim" style="font-size:0.78rem;white-space:normal">Poäng 0-100 = källans förtroende, extra källor och känd familj, minus åldersavdrag '
        '(IP 30 dagar, URL 14, domän 60, hash 180) och avdrag för värden som inte bör blockeras. Visar de 40 högst poängsatta. '
        'Blocklistor och STIX i exports/ använder samma poäng.</p>'
    )


if __name__ == "__main__":
    run_ioc_scores()
