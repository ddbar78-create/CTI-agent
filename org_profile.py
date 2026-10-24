"""
Hotprofil för din organisation och händelsetidslinje.

Hotprofil (sektionen "Hotprofil"): rankar grupper och sårbarheter efter hur relevanta de är för
just din organisation (config_org.py: sektor, land, teknikstack), med en mening som förklarar varför.

  Grupprelevans  = 4 x offer i din sektor (90 dagar) + 3 x offer i ditt land + 1,5 x övriga nordiska offer
                   + 5 x sårbarheter i din teknik som omnämns tillsammans med gruppen + 2 x veckans offer (max 5)
  CVE-relevans   = riskpoängen x 1,5 om den berör din teknik x 1,3 om en grupp som riktar sig mot din sektor nämns med den

Händelsetidslinje: tabellen events sparar när saker hände första gången (första omnämnande av en CVE,
CISA KEV-listning, ransomware-koppling, första offer, första nordiska offer, grupp och CVE nämnda tillsammans).
Händelserna sparas permanent, så historiken finns kvar även när gamla artiklar rensas. Tidslinjen visas
i entitetssök.
"""

import html
import sqlite3
from datetime import datetime, timedelta, timezone

from config_org import ORG
from storage import DB_PATH

NORDIC = {"SE", "NO", "DK", "FI", "IS"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    entity_type TEXT NOT NULL,
    entity TEXT NOT NULL,
    kind TEXT NOT NULL,
    day TEXT NOT NULL,
    detail TEXT,
    PRIMARY KEY (entity_type, entity, kind, day)
)
"""

KIND_LABELS = {
    "first_mention": "Första omnämnande", "kev_listed": "Lades till i CISA KEV", "ransomware_use": "Kopplad till ransomware",
    "tech_hit": "Berör din teknik", "first_victim": "Första kända offer", "first_nordic": "Första nordiska offer",
    "comention": "Omnämns tillsammans med", "sector_victim": "Första offer i din sektor",
}


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def _sector_keywords() -> list:
    try:
        from intel import SECTOR_FOCUS
        return SECTOR_FOCUS.get(ORG["sector"], [])
    except Exception:
        return []


# ------------------------------------------------------------------ händelser
def collect_events(ctx) -> list:
    """Returnerar [(entitetstyp, entitet, sort, dag, detalj)] ur kontexten från intel.load_context."""
    ev = []
    kws = _sector_keywords()
    by_group = {}
    for v in ctx["victims"]:
        by_group.setdefault(v["group"], []).append(v)
    for g, vs in by_group.items():
        days = sorted(v["day"] for v in vs if v["day"])
        if days:
            first = next(v for v in vs if v["day"] == days[0])
            ev.append(("group", g, "first_victim", str(days[0]), f"{first['victim']} ({first['cc'] or '?'})"))
        nd = sorted([v for v in vs if v["day"] and v["cc"] in NORDIC], key=lambda v: v["day"])
        if nd:
            ev.append(("group", g, "first_nordic", str(nd[0]["day"]), f"{nd[0]['victim']} ({nd[0]['cc']})"))
        sv = sorted([v for v in vs if v["day"] and kws and any(k in (v["sector"] or "").lower() for k in kws)], key=lambda v: v["day"])
        if sv:
            ev.append(("group", g, "sector_victim", str(sv[0]["day"]), f"{sv[0]['victim']} ({sv[0]['sector']})"))
    for c in ctx["cves"]:
        arts = [a for a in c["articles"] if a["day"]]
        if arts:
            first = min(arts, key=lambda a: a["day"])
            ev.append(("cve", c["id"], "first_mention", str(first["day"]), f"{first['feed']}: {first['title'][:90]}"))
            kev = [a for a in arts if a["feed"] == "CISA KEV"]
            if kev:
                ev.append(("cve", c["id"], "kev_listed", str(min(a["day"] for a in kev)), "CISA Known Exploited Vulnerabilities"))
        if c["ransom"] and c["checked"]:
            ev.append(("cve", c["id"], "ransomware_use", c["checked"][:10], "Markerad som använd av ransomware (CISA KEV)"))
        if c["tech"] and c["checked"]:
            ev.append(("cve", c["id"], "tech_hit", c["checked"][:10], ", ".join(c["tech"][:2])))
        for g in c["groups"]:
            shared = [a for a in arts if a["id"] in ctx["group_articles"].get(g, set())]
            if shared:
                d = str(min(a["day"] for a in shared))
                ev.append(("cve", c["id"], "comention", d, g))
                ev.append(("group", g, "comention", d, c["id"]))
    return ev


def run_events(db_path: str = DB_PATH) -> int:
    from intel import shared_context
    ctx = shared_context(db_path)
    ev = collect_events(ctx)
    conn = _connect(db_path)
    before = conn.total_changes
    conn.executemany("INSERT OR IGNORE INTO events (entity_type, entity, kind, day, detail) VALUES (?, ?, ?, ?, ?)", ev)
    conn.commit()
    new = conn.total_changes - before
    conn.close()
    print(f"[+] Händelser: {new} nya av {len(ev)} kontrollerade.")
    return new


def events_for(db_path: str, etype: str, name: str, limit: int = 14) -> list:
    try:
        conn = _connect(db_path)
        rows = conn.execute(
            "SELECT day, kind, detail FROM events WHERE entity_type = ? AND entity = ? ORDER BY day, kind LIMIT ?",
            (etype, name, limit)).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    return rows


def attach_timelines(ents: dict, db_path: str = DB_PATH):
    """Lägger till en tidslinje först i varje gruppens och CVE:s entitetssida."""
    for etype in ("group", "cve"):
        for name, ent in ents.get(etype, {}).items():
            rows = events_for(db_path, etype, name)
            if not rows:
                continue
            items = []
            for day, kind, detail in rows:
                label = KIND_LABELS.get(kind, kind)
                entity_ref = None
                if kind == "comention":
                    entity_ref = ["cve" if etype == "group" else "group", detail]
                    items.append({"t": detail, "u": "", "e": entity_ref, "d": f"{day} · {label}"})
                else:
                    items.append({"t": f"{label}: {detail}" if detail else label, "u": "", "e": None, "d": day})
            ent["lists"].insert(0, {"title": "Tidslinje", "items": items})


# ------------------------------------------------------------------ hotprofil
def compute_profile(ctx) -> dict:
    today = ctx["today"]
    kws = _sector_keywords()
    home = set(ORG["countries"])
    recent = [v for v in ctx["victims"] if v["day"] and (today - v["day"]).days <= 90]
    by_group = {}
    for v in recent:
        by_group.setdefault(v["group"], []).append(v)
    tech_cves = [c for c in ctx["cves"] if c["tech"] and c["score"] >= 30]
    groups = []
    for g, vs in by_group.items():
        sector_n = sum(1 for v in vs if kws and any(k in (v["sector"] or "").lower() for k in kws))
        home_n = sum(1 for v in vs if v["cc"] in home)
        nordic_other = sum(1 for v in vs if v["cc"] in NORDIC and v["cc"] not in home)
        week_n = sum(1 for v in vs if (today - v["day"]).days < 7)
        linked = [c for c in tech_cves if g in c["groups"]]
        score = 4 * sector_n + 3 * home_n + 1.5 * nordic_other + 5 * len(linked) + 2 * min(week_n, 5)
        if sector_n == 0 and home_n == 0 and not linked and nordic_other == 0:
            continue
        reasons = []
        if sector_n:
            reasons.append(f"{sector_n} offer inom {ORG['sector'].lower()} senaste 90 dagarna")
        if home_n:
            reasons.append(f"{home_n} offer i {', '.join(sorted(home))}")
        if nordic_other:
            reasons.append(f"{nordic_other} offer i övriga Norden")
        if linked:
            reasons.append("nämns med " + ", ".join(c["id"] for c in linked[:3]) + " i din teknik")
        if week_n:
            reasons.append(f"{week_n} offer senaste veckan")
        groups.append({"name": g, "score": round(score, 1), "reasons": reasons, "sector_n": sector_n, "week_n": week_n})
    groups.sort(key=lambda x: -x["score"])
    relevant_groups = {g["name"] for g in groups if g["sector_n"] > 0}
    cves = []
    for c in ctx["cves"]:
        rel = c["score"] * (1.5 if c["tech"] else 1) * (1.3 if relevant_groups & set(c["groups"]) else 1)
        if rel < 20:
            continue
        reasons = [l for l, _p in c["factors"][:3]]
        if c["tech"]:
            reasons.insert(0, "berör " + ", ".join(c["tech"][:2]))
        hit = sorted(relevant_groups & set(c["groups"]))
        if hit:
            reasons.append("nämns med " + ", ".join(hit[:2]) + " som riktar sig mot din sektor")
        cves.append({"id": c["id"], "score": round(rel), "base": c["score"], "reasons": reasons})
    cves.sort(key=lambda x: -x["score"])
    return {"groups": groups[:10], "cves": cves[:10]}


def profile_alerts(ctx) -> list:
    p = compute_profile(ctx)
    iso = ctx["today"].isocalendar()
    week = f"{iso[0]}-W{iso[1]:02d}"
    out = []
    for i, g in enumerate(p["groups"][:3]):
        if g["sector_n"] >= 1 and g["week_n"] >= 2:
            out.append({"kind": "profile", "level": "Hög", "key": f"profile:{g['name']}:{week}",
                        "title": f"{g['name']} är topp {i + 1} i din hotprofil och aktiv just nu",
                        "detail": "; ".join(g["reasons"][:3])})
    return out


PROFILE_CSS = """
  .op-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.2rem; }
  .op-row { padding: 0.45rem 0; border-bottom: 1px solid var(--panel-border); font-size: 0.85rem; display: grid; grid-template-columns: 2.4rem 1fr; gap: 0.6rem; }
  .op-rank { font-family: var(--mono, monospace); color: var(--text-dim); text-align: center; padding-top: 0.1rem; }
  .op-row small { display: block; color: var(--text-dim); font-size: 0.76rem; margin-top: 0.1rem; }
  .op-h { font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); margin: 0 0 0.4rem; }
  .op-top { display: flex; gap: 1.2rem; flex-wrap: wrap; margin-bottom: 1rem; font-size: 0.85rem; }
  .op-top div { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.4rem 0.8rem; }
  .op-top b { font-family: var(--mono, monospace); }
"""


def _surface_summary(db_path: str) -> str:
    parts = []
    try:
        conn = sqlite3.connect(db_path)
        n = conn.execute("SELECT COUNT(*), SUM(level = 'Kritisk') FROM surface_findings WHERE status = 'öppen'").fetchone()
        parts.append(f'Attackyta: <b>{n[0] or 0}</b> öppna fynd (<b>{n[1] or 0}</b> kritiska)')
        la = conn.execute("SELECT COUNT(*) FROM lookalike_domains WHERE score >= 60").fetchone()[0]
        parts.append(f'Look-alike-domäner med hög poäng: <b>{la}</b>')
        conn.close()
    except sqlite3.Error:
        pass
    return "".join(f"<div>{p}</div>" for p in parts)


def build_profile_html(ctx, db_path: str = DB_PATH) -> str:
    p = compute_profile(ctx)
    if not p["groups"] and not p["cves"]:
        return '<p class="empty">Ingen relevant aktivitet hittad ännu för din profil. Det fylls när fler offer och CVE:er samlats in.</p>'
    ent = lambda t, n: f'<button class="in-link" type="button" data-ent="{t}|{html.escape(n)}">{html.escape(n)}</button>'
    g_rows = "".join(
        f'<div class="op-row"><span class="op-rank">{i}</span><div>{ent("group", g["name"])} <span class="dim">({g["score"]})</span>'
        f'<small>{html.escape("; ".join(g["reasons"]))}</small></div></div>' for i, g in enumerate(p["groups"], 1))
    c_rows = "".join(
        f'<div class="op-row"><span class="op-rank">{i}</span><div>{ent("cve", c["id"])} <span class="dim">(relevans {c["score"]}, risk {c["base"]})</span>'
        f'<small>{html.escape("; ".join(c["reasons"]))}</small></div></div>' for i, c in enumerate(p["cves"], 1))
    return (
        f'<div class="op-top"><div>Organisation: <b>{html.escape(ORG["name"])}</b></div><div>Sektor: <b>{html.escape(ORG["sector"])}</b></div>'
        f'<div>Land: <b>{html.escape(", ".join(ORG["countries"]))}</b></div>{_surface_summary(db_path)}</div>'
        f'<div class="op-cols"><div><div class="op-h">Mest relevanta grupper</div>{g_rows or "<p class=dim>Inga ännu.</p>"}</div>'
        f'<div><div class="op-h">Sårbarheter att prioritera</div>{c_rows or "<p class=dim>Inga ännu.</p>"}</div></div>'
        '<p class="dim" style="font-size:0.78rem;white-space:normal;margin-top:0.8rem">Rankningen väger offer i din sektor och ditt land, nordiska offer, '
        'sårbarheter i din teknik och veckans aktivitet (se org_profile.py). Sektor, land och domäner ställs in i config_org.py, teknik i tech_watchlist.py.</p>')
