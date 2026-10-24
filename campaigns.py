"""
Kampanjgruppering — samlar artiklar som hör ihop till en kampanj.

Regler (regelbaserade, ingen LLM):
  - Två artiklar hör ihop om de delar en specifik indikator: samma CVE, eller samma domän, IP eller
    SHA-256-hash. Gruppnamn och vanliga ord knyter inte ihop artiklar på egen hand.
  - Entiteter som förekommer i fler än 40 artiklar (t.ex. en CVE som alla skriver om) ignoreras, liksom
    vanliga sajter (github.com m.fl.).
  - En kampanj är en sammanhängande grupp med minst 3 artiklar, eller 2 artiklar som delar minst 2 entiteter.
  - Kampanjen får ett stabilt id av sin första (alfabetiskt) delade entitet, och ett namn av grupperna och
    huvud-entiteten som nämns i den ("Qilin + CVE-2026-1001").
  - Varje kampanj visar varför den hänger ihop (de delade entiteterna).

Tabell: campaigns. Larm: ny kampanj (senaste 2 dagarna) som berör din teknik, din sektor eller Norden.
"""

import hashlib
import html
import json
import sqlite3
import sys
from collections import defaultdict
from datetime import timedelta

from config_org import ORG
from storage import DB_PATH

MAX_ENTITY_ARTICLES = 40
MIN_ARTICLES = 3
NORDIC_WORDS = ("sweden", "swedish", "sverige", "norway", "norwegian", "denmark", "danish", "finland", "finnish", "nordic", "scandinavia")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT, first_seen TEXT, last_seen TEXT, size INTEGER,
    entities TEXT, groups TEXT, articles TEXT, tech TEXT,
    relevant INTEGER DEFAULT 0, created_at TEXT
)
"""


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def _ioc_entities(db_path, article_ids) -> dict:
    """{artikel-id: {entitet,...}} för domäner, IP och SHA-256 som delas mellan artiklar."""
    from ioc_confidence import BENIGN_DOMAINS
    out = defaultdict(set)
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT article_id, ioc_type, value FROM iocs WHERE ioc_type IN ('domain', 'ipv4', 'sha256_hash')").fetchall()
        conn.close()
    except sqlite3.Error:
        return out
    ids = set(article_ids)
    for aid, t, v in rows:
        if aid not in ids:
            continue
        v = str(v).split(" [")[0].strip().lower()
        if t == "domain" and (v in BENIGN_DOMAINS or any(v.endswith("." + b) for b in BENIGN_DOMAINS)):
            continue
        out[aid].add(f"{t}:{v}")
    return out


def find_campaigns(ctx, db_path: str = DB_PATH) -> list:
    articles = ctx["articles"]
    ent_articles = defaultdict(set)
    for cve, aids in ctx["cve_articles"].items():
        for a in aids:
            if a in articles:
                ent_articles["cve:" + cve].add(a)
    for aid, ents in _ioc_entities(db_path, articles.keys()).items():
        for e in ents:
            ent_articles[e].add(aid)
    ent_articles = {e: a for e, a in ent_articles.items() if 2 <= len(a) <= MAX_ENTITY_ARTICLES}

    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for e, aids in ent_articles.items():
        aids = sorted(aids)
        for a in aids[1:]:
            parent[find(a)] = find(aids[0])
    comps = defaultdict(set)
    for a in list(parent):
        comps[find(a)].add(a)

    out = []
    for members in comps.values():
        shared = {e: a & members for e, a in ent_articles.items() if len(a & members) >= 2}
        if len(members) < MIN_ARTICLES and len(shared) < 2:
            continue
        groups = sorted(g for g, aids in ctx["group_articles"].items() if len(aids & members) >= 1)
        groups = sorted(groups, key=lambda g: -len(ctx["group_articles"][g] & members))[:3]
        main = max(shared, key=lambda e: (len(shared[e]), e)) if shared else ""
        days = [articles[a]["day"] for a in members if articles[a]["day"]]
        arts_sorted = sorted(members, key=lambda a: articles[a]["day"] or ctx["today"], reverse=True)
        text = " ".join(articles[a]["title"] + " " + articles[a]["summary"] for a in members).lower()
        from intel import _tech_for
        tech = _tech_for(text)
        sector_kw = []
        try:
            from intel import SECTOR_FOCUS
            sector_kw = SECTOR_FOCUS.get(ORG["sector"], [])
        except Exception:
            pass
        relevant = bool(tech) or any(k in text for k in sector_kw) or any(w in text for w in NORDIC_WORDS) \
            or any(b in text for b in ORG["brands"])
        name = " + ".join(groups[:2] + ([main.split(":", 1)[1]] if main else [])) or "Okänd kampanj"
        cid = hashlib.sha1(min(shared).encode()).hexdigest()[:10] if shared else hashlib.sha1(str(sorted(members)[:1]).encode()).hexdigest()[:10]
        out.append({
            "id": cid, "name": name, "first": str(min(days)) if days else "", "last": str(max(days)) if days else "",
            "size": len(members), "entities": sorted(shared, key=lambda e: -len(shared[e]))[:8], "groups": groups,
            "articles": arts_sorted[:8], "tech": tech, "relevant": int(relevant),
        })
    out.sort(key=lambda c: (c["last"], c["size"]), reverse=True)
    return out


def run_campaigns(db_path: str = DB_PATH) -> int:
    from intel import shared_context
    ctx = shared_context(db_path)
    camps = find_campaigns(ctx, db_path)
    conn = _connect(db_path)
    now = ctx["today"].isoformat()
    existing = {r[0] for r in conn.execute("SELECT id FROM campaigns")}
    conn.execute("DELETE FROM campaigns WHERE last_seen < ?", ((ctx["today"] - timedelta(days=90)).isoformat(),))
    for c in camps:
        conn.execute(
            """INSERT INTO campaigns (id, name, first_seen, last_seen, size, entities, groups, articles, tech, relevant, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, last_seen=excluded.last_seen, size=excluded.size,
                   entities=excluded.entities, groups=excluded.groups, articles=excluded.articles, tech=excluded.tech, relevant=excluded.relevant""",
            (c["id"], c["name"], c["first"], c["last"], c["size"], json.dumps(c["entities"]), json.dumps(c["groups"]),
             json.dumps(c["articles"]), json.dumps(c["tech"]), c["relevant"], now))
    conn.commit()
    conn.close()
    new = sum(1 for c in camps if c["id"] not in existing)
    print(f"[+] Kampanjer: {len(camps)} hittade, {new} nya.", file=sys.stdout)
    return new


def campaign_alerts(db_path: str = DB_PATH) -> list:
    try:
        conn = _connect(db_path)
        from datetime import datetime, timezone
        cutoff = (datetime.now(timezone.utc).date() - timedelta(days=2)).isoformat()
        rows = conn.execute(
            "SELECT id, name, size, entities FROM campaigns WHERE relevant = 1 AND created_at >= ? ORDER BY size DESC LIMIT 10", (cutoff,)).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    return [{"kind": "campaign", "level": "Hög", "key": f"campaign:{i}",
             "title": f"Ny kampanj som kan beröra dig: {n}", "detail": f"{s} artiklar delar {', '.join(json.loads(e)[:3])}"} for i, n, s, e in rows]


CAMPAIGN_CSS = """
  .cp-card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.7rem 1rem; margin-bottom: 0.7rem; font-size: 0.85rem; }
  .cp-card h4 { margin: 0 0 0.25rem; font-size: 0.95rem; display: flex; gap: 0.5rem; align-items: baseline; flex-wrap: wrap; }
  .cp-card .dim { font-size: 0.76rem; }
  .cp-card ul { margin: 0.35rem 0 0; padding-left: 1.1rem; font-size: 0.8rem; }
  .cp-tag { font-size: 0.68rem; padding: 0.05rem 0.5rem; border-radius: 9px; border: 1px solid var(--amber); color: var(--amber); }
"""


def build_campaigns_html(db_path: str = DB_PATH) -> str:
    try:
        conn = _connect(db_path)
        rows = conn.execute(
            "SELECT id, name, first_seen, last_seen, size, entities, groups, articles, tech, relevant FROM campaigns "
            "ORDER BY relevant DESC, last_seen DESC, size DESC LIMIT 15").fetchall()
        arts = {}
        for r in rows:
            for a in json.loads(r[7]):
                arts[a] = None
        if arts:
            q = ",".join("?" * len(arts))
            for aid, title, link, feed in conn.execute(f"SELECT id, title, link, feed FROM articles WHERE id IN ({q})", list(arts)):
                arts[aid] = (title, link, feed)
        conn.close()
    except sqlite3.Error:
        rows, arts = [], {}
    if not rows:
        return ('<p class="empty">Inga kampanjer hittade ännu. En kampanj kräver minst tre artiklar som delar en CVE eller indikator '
                '(eller två artiklar som delar två), så den fylls på med tiden.</p>')
    cards = []
    for cid, name, first, last, size, ents, groups, art_ids, tech, relevant in rows:
        links = "".join(
            f'<li><a href="{html.escape(arts[a][1])}" target="_blank" rel="noopener">{html.escape(arts[a][0][:100])}</a> <span class="dim">{html.escape(arts[a][2])}</span></li>'
            for a in json.loads(art_ids)[:4] if arts.get(a))
        tags = ("<span class='cp-tag'>kan beröra dig</span>" if relevant else "") + "".join(f"<span class='cp-tag'>{html.escape(t)}</span>" for t in json.loads(tech)[:2])
        cards.append(
            f'<div class="cp-card"><h4>{html.escape(name)} {tags}</h4>'
            f'<div class="dim">{html.escape(first)} till {html.escape(last)} · {size} artiklar · delar: {html.escape(", ".join(json.loads(ents)[:5]))}</div>'
            f'<ul>{links}</ul></div>')
    return "".join(cards) + ('<p class="dim" style="font-size:0.78rem;white-space:normal">Artiklar grupperas när de delar en specifik indikator '
                             '(CVE, domän, IP eller hash). Regelbaserat, så ibland hänger sådant ihop som inte hör ihop: kontrollera "delar" på varje kort.</p>')
