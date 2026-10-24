"""
Intel — analysfunktioner i stil med kommersiella CTI-plattformar, helt utan LLM och utan nycklar.
Allt byggs av data som agenten redan har samlat in i cti.db.

Sektioner som genereras (se build_intel_blocks):
  alerts     Larm & avvikelser: ovanligt mycket aktivitet, nya aktörer, nordiska offer i din sektor,
             aktivt utnyttjade sårbarheter som berör din teknik
  sectorrep  Sektorrapport för transport och offentlig sektor (regelbaserad text, kan laddas ner)
  cvescore   CVE-riskpoäng 0-100 med förklaring per faktor ("patcha detta först")
  graph      Relationsgraf: grupper, branscher, länder och CVE:er som hänger ihop
  entity     Entitetssök: klicka på en grupp, CVE, bransch eller land och se allt kopplat

compute_alerts() används även av notifier.py för mejl/Discord/Teams/ntfy.

Justera SECTOR_FOCUS nedan om du vill bevaka andra branscher.
"""

import html
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from storage import DB_PATH

try:  # teknikbevakningen (valfri)
    from tech_watch import _COMPILED as TECH_RX
except Exception:  # pragma: no cover
    TECH_RX = []

NORDIC = {"SE", "NO", "DK", "FI", "IS"}
NORDIC_NAMES = {"SE": "Sverige", "NO": "Norge", "DK": "Danmark", "FI": "Finland", "IS": "Island"}

# Branscher du bevakar: namn -> nyckelord (gemener) som matchas mot offrets bransch och mot artikeltitlar.
SECTOR_FOCUS = {
    "Transport och logistik": [
        "transport", "logistic", "shipping", "maritime", "aviation", "airline", "airport", "railway",
        "freight", "port authority", "trucking", "cargo", "ferry", "public transit",
    ],
    "Offentlig sektor": [
        "government", "public sector", "public administration", "municipal", "municipality", "kommun",
        "county", "city of", "ministry", "council", "police", "public service", "regional",
    ],
}

# Gruppnamn som är vanliga ord: kräver ordet "ransomware" i artikeln för att räknas som omnämnande.
AMBIGUOUS_GROUPS = {"play", "hunters", "lynx", "cloak", "pear", "sarcoma", "money message", "everest", "orca"}

LEVEL_ORDER = {"Kritisk": 0, "Hög": 1, "Medel": 2, "Info": 3}


# ------------------------------------------------------------------ hjälp
def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _today():
    return datetime.now(timezone.utc).date()


def _d(s):
    try:
        return datetime.strptime((s or "")[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _q(conn, sql, params=()):
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []


def _week_index(day, today):
    return (today - day).days // 7 if day else None


def _canon_groups(names):
    spelling = defaultdict(Counter)
    for n in names:
        spelling[n.strip().lower()][n.strip()] += 1
    return {k: v.most_common(1)[0][0] for k, v in spelling.items()}


def _shorten(s, n):
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


# ------------------------------------------------------------------ datainläsning
def load_context(db_path: str = DB_PATH) -> dict:
    today = _today()
    conn = sqlite3.connect(db_path)

    victims_raw = []
    attempts = (
        "SELECT group_name, country, sector, COALESCE(NULLIF(attack_date,''), substr(first_seen,1,10)), victim, COALESCE(first_seen,'') "
        "FROM ransomware_victims WHERE group_name IS NOT NULL AND group_name != '' ORDER BY id DESC LIMIT 6000",
        "SELECT group_name, country, sector, attack_date, victim, '' "
        "FROM ransomware_victims WHERE group_name IS NOT NULL AND group_name != '' ORDER BY id DESC LIMIT 6000",
    )
    for sql in attempts:
        r = _q(conn, sql)
        if r:
            victims_raw = r
            break
    try:
        from aliases import canonical as _alias
    except Exception:  # pragma: no cover
        _alias = lambda n, *a, **k: n
    victims_raw = [(_alias(r[0], db_path),) + tuple(r[1:]) for r in victims_raw]
    canon = _canon_groups([v[0] for v in victims_raw])
    victims = []
    for g, cc, sec, day, vic, seen in victims_raw:
        dd = _d(day)
        victims.append({
            "group": canon[g.strip().lower()], "cc": (cc or "").strip().upper(), "sector": (sec or "").strip(),
            "day": dd, "victim": (vic or "").strip(), "seen": seen or "",
        })

    cutoff = (today - timedelta(days=60)).isoformat()
    articles = {}
    for aid, feed, title, link, fetched, summ in _q(
        conn,
        "SELECT id, feed, title, link, COALESCE(fetched_at,''), COALESCE(substr(summary,1,600),'') "
        "FROM articles WHERE substr(fetched_at,1,10) >= ? ORDER BY id DESC LIMIT 6000",
        (cutoff,),
    ):
        articles[aid] = {"id": aid, "feed": feed, "title": title, "link": link, "day": _d(fetched), "summary": summ}

    cve_articles = defaultdict(set)
    for aid, val in _q(conn, "SELECT article_id, upper(value) FROM iocs WHERE ioc_type = 'cve'"):
        if aid in articles:
            cve_articles[val].add(aid)

    cve_rows = {}
    for cid, cvss, epss, kev, ransom, summ, checked in _q(
        conn, "SELECT cve_id, cvss, epss, kev, ransomware_campaign, summary, COALESCE(checked_at,'') FROM cve_enrichment"
    ):
        cve_rows[cid.upper()] = {
            "id": cid.upper(), "cvss": cvss, "epss": epss, "kev": bool(kev),
            "ransom": (ransom or "").strip().lower() == "known", "summary": summ or "", "checked": checked,
        }
    conn.close()

    ctx = {"today": today, "victims": victims, "articles": articles, "cve_articles": cve_articles, "cve_rows": cve_rows}
    _link_group_mentions(ctx)
    _score_all_cves(ctx)
    return ctx


_CTX_CACHE = {}


def shared_context(db_path: str = DB_PATH, ttl: int = 300) -> dict:
    """Samma kontext återanvänds inom en körning (flera moduler behöver den). Går ut efter ttl sekunder."""
    import time
    hit = _CTX_CACHE.get(db_path)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    ctx = load_context(db_path)
    _CTX_CACHE[db_path] = (time.time(), ctx)
    return ctx


def _link_group_mentions(ctx):
    cnt = Counter(v["group"] for v in ctx["victims"] if v["day"] and (ctx["today"] - v["day"]).days <= 120)
    names = [g for g, c in cnt.items() if c >= 2 and len(g) >= 3]
    ctx["group_articles"] = defaultdict(set)
    if not names:
        return
    by_lower = {n.lower(): n for n in names}
    rx = re.compile(
        r"(?<![a-z0-9])(" + "|".join(re.escape(n) for n in sorted(by_lower, key=len, reverse=True)) + r")(?![a-z0-9])"
    )
    for aid, a in ctx["articles"].items():
        text = (a["title"] + " " + a["summary"]).lower()
        found = {m.group(1) for m in rx.finditer(text)}
        for low in found:
            if low in AMBIGUOUS_GROUPS and "ransomware" not in text:
                continue
            ctx["group_articles"][by_lower[low]].add(aid)


# ------------------------------------------------------------------ CVE-riskpoäng
def _tech_for(text):
    found = []
    for name, rx in TECH_RX:
        if rx and rx.search(text):
            found.append(name)
    return found


def score_cve(row, mentions, feeds, tech):
    """Returnerar (poäng 0-100, [(faktor, poäng), ...]). Maxpoäng: 25+25+25+10+8+7 = 100."""
    f = []
    if row.get("cvss") is not None:
        f.append((f"CVSS {row['cvss']:.1f}", round(row["cvss"] / 10 * 25)))
    if row.get("epss") is not None:
        f.append((f"EPSS {row['epss']:.0%} sannolikhet för utnyttjande", round(min(row["epss"], 0.6) / 0.6 * 25)))
    if row.get("kev"):
        f.append(("Aktivt utnyttjad (CISA KEV)", 25))
    if row.get("ransom"):
        f.append(("Används av ransomware-grupper", 10))
    if mentions:
        f.append((f"Omnämnd i {mentions} artikel{'ar' if mentions > 1 else ''} ({feeds} källa{'or' if feeds > 1 else ''})",
                  min(8, round(2 * math.log2(1 + mentions)))))
    if tech:
        f.append((f"Berör din teknik: {', '.join(tech[:2])}", 7))
    return min(100, sum(p for _l, p in f)), f


def _level(score):
    return "Kritisk" if score >= 75 else "Hög" if score >= 50 else "Medel" if score >= 30 else "Låg"


def _score_all_cves(ctx):
    ids = set(ctx["cve_rows"]) | set(ctx["cve_articles"])
    out = []
    for cid in ids:
        row = ctx["cve_rows"].get(cid, {"id": cid, "cvss": None, "epss": None, "kev": False, "ransom": False, "summary": "", "checked": ""})
        arts = [ctx["articles"][a] for a in ctx["cve_articles"].get(cid, ()) if a in ctx["articles"]]
        arts.sort(key=lambda a: a["day"] or datetime.min.date(), reverse=True)
        feeds = len({a["feed"] for a in arts})
        text = cid + " " + row["summary"] + " " + " ".join(a["title"] for a in arts[:6])
        tech = _tech_for(text)
        score, factors = score_cve(row, len(arts), feeds, tech)
        groups = sorted({g for g, aids in ctx["group_articles"].items() if aids & ctx["cve_articles"].get(cid, set())})
        out.append({**row, "score": score, "level": _level(score), "factors": factors, "mentions": len(arts),
                    "tech": tech, "articles": arts, "groups": groups,
                    "last": (arts[0]["day"] if arts else None)})
    # CVE:er utan någon data alls (inga berikningsfält, inga omnämnanden) är brus
    out = [c for c in out if c["factors"]]
    out.sort(key=lambda c: (c["score"], c["mentions"]), reverse=True)
    ctx["cves"] = out


# ------------------------------------------------------------------ avvikelser och larm
def _focus_sector_of(sector_text):
    low = (sector_text or "").lower()
    for name, kws in SECTOR_FOCUS.items():
        if any(k in low for k in kws):
            return name
    return None


def compute_alerts(db_path: str = DB_PATH, ctx: dict = None) -> list:
    ctx = ctx or load_context(db_path)
    today = ctx["today"]
    iso = today.isocalendar()
    week_key = f"{iso[0]}-W{iso[1]:02d}"
    alerts = []

    def add(kind, level, title, detail, key):
        alerts.append({"kind": kind, "level": level, "title": title, "detail": detail, "key": key})

    by_group = defaultdict(list)
    for v in ctx["victims"]:
        by_group[v["group"]].append(v)

    for g, vs in by_group.items():
        weeks = Counter(_week_index(v["day"], today) for v in vs if v["day"])
        nweeks = Counter(_week_index(v["day"], today) for v in vs if v["day"] and v["cc"] in NORDIC)
        recent, recent_n = weeks.get(0, 0), nweeks.get(0, 0)
        base = [weeks.get(i, 0) for i in range(1, 9)]
        base_n = [nweeks.get(i, 0) for i in range(1, 9)]
        mean, mean_n = sum(base) / 8, sum(base_n) / 8
        if recent_n >= 2 and recent_n >= 2 * mean_n + 1:
            add("nordic_spike", "Hög", f"{g}: ovanligt många nordiska offer",
                f"{recent_n} nordiska offer senaste 7 dagarna (normalt ca {mean_n:.1f} per vecka).", f"nspike:{g}:{week_key}")
        elif recent >= 3 and recent >= 2.5 * mean and recent - mean >= 2:
            add("group_spike", "Medel", f"{g}: kraftigt ökad aktivitet",
                f"{recent} offer senaste 7 dagarna (normalt ca {mean:.1f} per vecka).", f"gspike:{g}:{week_key}")
        days = [v["day"] for v in vs if v["day"]]
        if days and len(vs) >= 2 and (today - min(days)).days <= 14:
            add("new_group", "Medel", f"Ny aktör: {g}", f"Första offret {min(days)}, totalt {len(vs)} offer hittills.", f"newgroup:{g}")

    # branschavvikelser (global)
    for name in SECTOR_FOCUS:
        weeks = Counter(_week_index(v["day"], today) for v in ctx["victims"] if v["day"] and _focus_sector_of(v["sector"]) == name)
        recent = weeks.get(0, 0)
        mean = sum(weeks.get(i, 0) for i in range(1, 9)) / 8
        if recent >= 5 and recent >= 2 * mean:
            add("sector_spike", "Medel", f"{name}: ökning av ransomware-offer",
                f"{recent} offer globalt senaste 7 dagarna (normalt ca {mean:.1f}).", f"sspike:{name}:{week_key}")

    # nordiska offer i bevakade branscher
    for v in ctx["victims"]:
        if v["cc"] in NORDIC and v["day"] and (today - v["day"]).days <= 7:
            focus = _focus_sector_of(v["sector"])
            if focus:
                add("nordic_focus_victim", "Hög", f"Nordiskt offer inom {focus.lower()}",
                    f"{v['victim']} ({NORDIC_NAMES.get(v['cc'], v['cc'])}, {v['day']}) – {v['group']}",
                    f"fvictim:{v['group']}:{v['victim']}"[:200])

    # nya aktivt utnyttjade sårbarheter som berör din teknik
    for a in ctx["articles"].values():
        if a["feed"] == "CISA KEV" and a["day"] and (today - a["day"]).days <= 3:
            techs = _tech_for(a["title"])
            if techs:
                m = re.search(r"CVE-\d{4}-\d{4,7}", a["title"])
                cid = m.group(0).upper() if m else a["title"][:30]
                row = ctx["cve_rows"].get(cid, {})
                lvl = "Kritisk" if row.get("ransom") else "Hög"
                add("kev_tech", lvl, f"Aktivt utnyttjad sårbarhet i din teknik: {techs[0]}",
                    f"{cid}: {_shorten(a['title'], 140)}" + (" – används av ransomware" if row.get("ransom") else ""), f"kevtech:{cid}")

    # CVE:er som precis nått mycket hög riskpoäng
    for c in ctx["cves"][:30]:
        fresh = c["checked"][:10] >= (today - timedelta(days=2)).isoformat() if c["checked"] else False
        if c["score"] >= 85 and fresh:
            add("cve_risk", "Hög", f"{c['id']} har hög riskpoäng ({c['score']}/100)",
                "; ".join(l for l, _p in c["factors"][:3]), f"cverisk:{c['id']}")

    # larm från de andra modulerna (alla valfria: saknas en modul hoppas den över)
    for mod, fn, arg in (("attack_surface", "surface_alerts", db_path), ("lookalike", "lookalike_alerts", db_path),
                         ("campaigns", "campaign_alerts", db_path), ("org_profile", "profile_alerts", ctx)):
        try:
            alerts.extend(getattr(__import__(mod), fn)(arg))
        except Exception as e:
            print(f"    Larm från {mod} kunde inte hämtas: {type(e).__name__}: {e}")

    alerts.sort(key=lambda a: LEVEL_ORDER.get(a["level"], 9))
    seen, unique = set(), []
    for a in alerts:
        if a["key"] not in seen:
            seen.add(a["key"])
            unique.append(a)
    return unique


# ------------------------------------------------------------------ entiteter
def _top(counter, n):
    return [[k, c] for k, c in counter.most_common(n) if k]


def _item(t, u="", e=None, d=""):
    return {"t": t, "u": u or "", "e": e, "d": d}


def build_entities(ctx, db_path: str = DB_PATH) -> dict:
    today = ctx["today"]
    ents = {"group": {}, "cve": {}, "sector": {}, "country": {}}
    victims = ctx["victims"]
    cve_by_id = {c["id"]: c for c in ctx["cves"]}

    by_group, by_sector, by_country = defaultdict(list), defaultdict(list), defaultdict(list)
    for v in victims:
        by_group[v["group"]].append(v)
        if v["sector"]:
            by_sector[v["sector"]].append(v)
        if v["cc"]:
            by_country[v["cc"]].append(v)

    def spark(vs):
        w = Counter(_week_index(v["day"], today) for v in vs if v["day"])
        return [w.get(i, 0) for i in range(11, -1, -1)]

    def recent_victims(vs, n=8, with_group=True):
        vs2 = sorted([v for v in vs if v["day"]], key=lambda v: v["day"], reverse=True)[:n]
        return [_item(v["victim"], "", ["group", v["group"]] if with_group else None,
                      f"{v['cc'] or '?'} · {v['day']}" + (f" · {v['group']}" if with_group else "")) for v in vs2]

    def art_items(aids, n=8):
        arts = sorted((ctx["articles"][a] for a in aids if a in ctx["articles"]), key=lambda a: a["day"] or datetime.min.date(), reverse=True)[:n]
        return [_item(_shorten(a["title"], 110), a["link"], None, f"{a['feed']} · {a['day'] or ''}") for a in arts]

    # grupper
    for g, vs in sorted(by_group.items(), key=lambda kv: -len(kv[1]))[:70]:
        days = [v["day"] for v in vs if v["day"]]
        nordic = sum(1 for v in vs if v["cc"] in NORDIC)
        cves = []
        for cid, c in cve_by_id.items():
            if g in c["groups"]:
                cves.append(c)
        cves.sort(key=lambda c: -c["score"])
        ents["group"][g] = {
            "type": "group", "name": g, "sub": "Ransomware-grupp",
            "kpis": [["offer", len(vs)], ["nordiska", nordic, nordic > 0],
                     ["första offer", str(min(days)) if days else "?"], ["senaste", str(max(days)) if days else "?"]],
            "spark": spark(vs),
            "bars": [{"title": "Länder", "pairs": [[k, c, ["country", k]] for k, c in _top(Counter(v["cc"] for v in vs), 6)]},
                     {"title": "Branscher", "pairs": [[k, c, ["sector", k]] for k, c in _top(Counter(v["sector"] for v in vs), 6)]}],
            "lists": [
                {"title": "Senaste offer", "items": recent_victims(vs, 8, False)},
                {"title": "Kopplade sårbarheter (omnämns tillsammans)", "items": [_item(c["id"], "", ["cve", c["id"]], f"risk {c['score']}") for c in cves[:6]]},
                {"title": "Senaste artiklar som nämner gruppen", "items": art_items(ctx["group_articles"].get(g, ()), 8)},
            ],
        }

    # CVE:er
    for c in ctx["cves"][:150]:
        ents["cve"][c["id"]] = {
            "type": "cve", "name": c["id"], "sub": f"Sårbarhet · {c['level']} risk",
            "kpis": [["riskpoäng", c["score"], c["score"] >= 75], ["CVSS", f"{c['cvss']:.1f}" if c["cvss"] is not None else "?"],
                     ["EPSS", f"{c['epss']:.0%}" if c["epss"] is not None else "?"], ["KEV", "ja" if c["kev"] else "nej", c["kev"]]],
            "note": _shorten(c["summary"], 400),
            "bars": [{"title": "Varför den här poängen", "pairs": [[l, p, None] for l, p in c["factors"]]}],
            "lists": [
                {"title": "Grupper som nämns i samma artiklar", "items": [_item(g, "", ["group", g]) for g in c["groups"][:8]]},
                {"title": "Din teknik", "items": [_item(t) for t in c["tech"]]},
                {"title": "Artiklar", "items": [_item(_shorten(a["title"], 110), a["link"], None, f"{a['feed']} · {a['day'] or ''}") for a in c["articles"][:8]]},
            ],
        }

    # branscher och länder
    def group_bars(vs):
        return [[k, c, ["group", k]] for k, c in _top(Counter(v["group"] for v in vs), 6)]

    for s, vs in sorted(by_sector.items(), key=lambda kv: -len(kv[1]))[:40]:
        ents["sector"][s] = {
            "type": "sector", "name": s, "sub": "Bransch",
            "kpis": [["offer", len(vs)], ["nordiska", sum(1 for v in vs if v["cc"] in NORDIC), any(v["cc"] in NORDIC for v in vs)],
                     ["grupper", len({v["group"] for v in vs})]],
            "spark": spark(vs),
            "bars": [{"title": "Aktivaste grupper", "pairs": group_bars(vs)},
                     {"title": "Länder", "pairs": [[k, c, ["country", k]] for k, c in _top(Counter(v["cc"] for v in vs), 6)]}],
            "lists": [{"title": "Senaste offer", "items": recent_victims(vs, 10)}],
        }
    for cc, vs in sorted(by_country.items(), key=lambda kv: -len(kv[1]))[:50]:
        ents["country"][cc] = {
            "type": "country", "name": cc, "sub": "Land" + (" (Norden)" if cc in NORDIC else ""),
            "kpis": [["offer", len(vs)], ["grupper", len({v["group"] for v in vs})]],
            "spark": spark(vs),
            "bars": [{"title": "Aktivaste grupper", "pairs": group_bars(vs)},
                     {"title": "Branscher", "pairs": [[k, c, ["sector", k]] for k, c in _top(Counter(v["sector"] for v in vs), 6)]}],
            "lists": [{"title": "Senaste offer", "items": recent_victims(vs, 10)}],
        }
    try:
        from aliases import aliases_of
        for g, ent in ents["group"].items():
            al = aliases_of(g, db_path)
            if al:
                ent["sub"] = "Ransomware-grupp · även känd som " + ", ".join(al[:4])
    except Exception:
        pass
    try:
        from org_profile import attach_timelines
        attach_timelines(ents, db_path)
    except Exception as e:
        print(f"    Tidslinjer kunde inte läggas till: {type(e).__name__}: {e}")
    return ents


# ------------------------------------------------------------------ relationsgraf
def build_graph(ctx) -> dict:
    today = ctx["today"]
    vs = [v for v in ctx["victims"] if v["day"] and (today - v["day"]).days <= 90]
    top_groups = [g for g, _c in Counter(v["group"] for v in vs).most_common(12)]
    nodes, links = {}, defaultdict(int)

    def node(nid, label, typ, w=1):
        n = nodes.setdefault(nid, {"id": nid, "label": label, "type": typ, "w": 0})
        n["w"] += w

    cve_by_id = {c["id"]: c for c in ctx["cves"]}
    for g in top_groups:
        gv = [v for v in vs if v["group"] == g]
        node("g:" + g, g, "group", len(gv))
        for s, c in Counter(v["sector"] for v in gv if v["sector"]).most_common(3):
            node("s:" + s, _shorten(s, 26), "sector", c)
            links[("g:" + g, "s:" + s)] += c
        for cc, c in Counter(v["cc"] for v in gv if v["cc"] in NORDIC).most_common():
            node("c:" + cc, NORDIC_NAMES.get(cc, cc), "nordic", c)
            links[("g:" + g, "c:" + cc)] += c
        top_countries = [cc for cc, _c in Counter(v["cc"] for v in gv if v["cc"] and v["cc"] not in NORDIC).most_common(2)]
        for cc in top_countries:
            node("c:" + cc, cc, "country", 1)
            links[("g:" + g, "c:" + cc)] += Counter(v["cc"] for v in gv)[cc]
        cves = sorted((c for c in cve_by_id.values() if g in c["groups"]), key=lambda c: -c["score"])[:2]
        for c in cves:
            node("v:" + c["id"], c["id"], "cve", max(1, c["score"] // 25))
            links[("g:" + g, "v:" + c["id"])] += 1
    return {"nodes": list(nodes.values()), "links": [{"s": a, "t": b, "w": w} for (a, b), w in links.items()]}


# ------------------------------------------------------------------ sektorrapport
def build_sector_reports(ctx) -> list:
    today = ctx["today"]
    reports = []
    for name, kws in SECTOR_FOCUS.items():
        match = lambda text: any(k in (text or "").lower() for k in kws)
        vs = [v for v in ctx["victims"] if v["day"] and _focus_sector_of(v["sector"]) == name]
        w0 = [v for v in vs if 0 <= (today - v["day"]).days < 7]
        w1 = [v for v in vs if 7 <= (today - v["day"]).days < 14]
        n0 = [v for v in w0 if v["cc"] in NORDIC]
        nordic30 = sorted([v for v in vs if v["cc"] in NORDIC and (today - v["day"]).days <= 30], key=lambda v: v["day"], reverse=True)
        top_groups = Counter(v["group"] for v in w0).most_common(4)
        arts = [a for a in ctx["articles"].values() if a["day"] and (today - a["day"]).days <= 7 and match(a["title"])]
        arts.sort(key=lambda a: a["day"], reverse=True)
        art_ids = {a["id"] for a in arts}
        cves = [c for c in ctx["cves"] if {x["id"] for x in c["articles"]} & art_ids][:5]

        delta = len(w0) - len(w1)
        trend = "oförändrat" if delta == 0 else (f"upp {delta}" if delta > 0 else f"ned {-delta}")
        lines = [f"Under de senaste sju dagarna har {len(w0)} ransomware-offer inom {name.lower()} noterats globalt "
                 f"(föregående vecka: {len(w1)}, {trend})."]
        if top_groups:
            lines.append("Mest aktiva grupper: " + ", ".join(f"{g} ({c})" for g, c in top_groups) + ".")
        lines.append(f"Av veckans offer var {len(n0)} nordiska." if n0 else "Inga nordiska offer inom branschen noterades den senaste veckan.")
        if nordic30:
            lines.append(f"Senaste 30 dagarna: {len(nordic30)} nordiska offer inom branschen.")
        if cves:
            lines.append("Sårbarheter som omnämns i branschrelaterade artiklar: " + ", ".join(f"{c['id']} (risk {c['score']})" for c in cves) + ".")
        reports.append({"name": name, "lines": lines, "nordic": nordic30[:8], "articles": arts[:6], "cves": cves,
                        "w0": len(w0), "w1": len(w1)})
    return reports


def _report_markdown(reports, today) -> str:
    md = [f"# Sektorrapport {today}", ""]
    for r in reports:
        md += [f"## {r['name']}", ""] + [f"- {l}" for l in r["lines"]] + [""]
        if r["nordic"]:
            md += ["**Nordiska offer (30 dagar)**", ""] + [f"- {v['victim']} ({v['cc']}, {v['day']}) – {v['group']}" for v in r["nordic"]] + [""]
        if r["articles"]:
            md += ["**Relevanta artiklar**", ""] + [f"- [{a['title']}]({a['link']})" for a in r["articles"]] + [""]
    return "\n".join(md)


# ------------------------------------------------------------------ HTML
INTEL_CSS = """
  .in-badge { display: inline-block; font-size: 0.68rem; padding: 0.05rem 0.5rem; border-radius: 9px; border: 1px solid var(--panel-border); margin-right: 0.4rem; white-space: nowrap; }
  .in-badge.Kritisk { color: #fff; background: var(--red); border-color: var(--red); }
  .in-badge.Hög { color: var(--red); border-color: var(--red); }
  .in-badge.Medel { color: var(--amber); border-color: var(--amber); }
  .in-badge.Info, .in-badge.Låg { color: var(--text-dim); }
  .in-alert { display: grid; grid-template-columns: 5.5rem 1fr; gap: 0.6rem; padding: 0.5rem 0.2rem; border-bottom: 1px solid var(--panel-border); font-size: 0.86rem; }
  .in-alert small { color: var(--text-dim); display: block; margin-top: 0.1rem; }
  .in-note { font-size: 0.78rem; color: var(--text-dim); margin: 0.6rem 0 0; white-space: normal; }
  .in-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  .in-table th { text-align: left; font-weight: 500; color: var(--text-dim); font-size: 0.74rem; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--panel-border); }
  .in-table td { padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--panel-border); vertical-align: middle; }
  .in-table td.num { font-family: var(--mono, monospace); text-align: right; white-space: nowrap; }
  .in-link { color: var(--amber); cursor: pointer; text-decoration: none; border-bottom: 1px dotted var(--amber); background: none; border-top: 0; border-left: 0; border-right: 0; font: inherit; padding: 0; }
  .in-score { display: inline-block; min-width: 2.2rem; text-align: center; border-radius: 4px; padding: 0.1rem 0.35rem; font-family: var(--mono, monospace); font-weight: 600; color: #fff; }
  .in-score.Kritisk { background: var(--red); } .in-score.Hög { background: #d9622b; } .in-score.Medel { background: #b8862a; } .in-score.Låg { background: #4b5563; }
  .in-bar { display: block; height: 5px; border-radius: 3px; background: var(--amber); margin-top: 3px; }
  .in-filters { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.7rem; align-items: center; }
  .in-filters button, .in-filters select, .in-filters input { background: var(--panel); color: var(--text); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.3rem 0.65rem; font-size: 0.8rem; font-family: inherit; cursor: pointer; }
  .in-filters button.active { border-color: var(--amber); color: var(--amber); }
  .in-reports { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
  .in-card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.9rem 1.1rem; font-size: 0.86rem; }
  .in-card h4 { margin: 0 0 0.5rem; font-size: 1rem; }
  .in-card p { margin: 0.3rem 0; white-space: normal; }
  .in-card ul { margin: 0.2rem 0 0.4rem; padding-left: 1.1rem; }
  .in-card h5 { margin: 0.8rem 0 0.2rem; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-dim); }
  .in-graph { background: #04070d; border: 1px solid #12305a; border-radius: 8px; position: relative; overflow: hidden; }
  .in-graph svg { width: 100%; height: 520px; display: block; }
  .in-legend { position: absolute; left: 0.7rem; bottom: 0.5rem; font-size: 0.72rem; color: #9fc4ff; display: flex; gap: 0.8rem; flex-wrap: wrap; pointer-events: none; }
  .in-legend i { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 4px; }
  .in-gmsg { padding: 0.8rem; color: #9fc4ff; font-size: 0.8rem; }
  .in-ent-head { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.8rem; }
  .in-ent-head input { flex: 1; min-width: 14rem; background: var(--panel); color: var(--text); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.45rem 0.7rem; font-size: 0.9rem; }
  .in-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 0.5rem; margin: 0.7rem 0; }
  .in-kpi { background: var(--bg); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.45rem 0.7rem; }
  .in-kpi b { display: block; font-size: 1.15rem; font-family: var(--mono, monospace); } .in-kpi.alert b { color: var(--red); }
  .in-kpi span { font-size: 0.7rem; color: var(--text-dim); }
  .in-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.1rem; }
  .in-bars div.r { display: grid; grid-template-columns: 14rem 1fr 2rem; gap: 0.4rem; align-items: center; font-size: 0.8rem; padding: 0.1rem 0; }
  .in-bars .v { font-family: var(--mono, monospace); text-align: right; color: var(--text-dim); font-size: 0.75rem; }
  .in-bars .lab { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .in-list { margin: 0; padding-left: 1.1rem; font-size: 0.82rem; }
  .in-list li { margin-bottom: 0.25rem; } .in-list small { color: var(--text-dim); }
  .in-spark { display: flex; align-items: flex-end; gap: 3px; height: 36px; margin: 0.4rem 0; }
  .in-spark i { flex: 1; background: var(--amber); min-width: 3px; border-radius: 2px 2px 0 0; opacity: 0.85; }
"""


def _alerts_html(alerts) -> str:
    if not alerts:
        return ('<p class="empty">Inga avvikelser just nu. Larmen jämför senaste veckan med de åtta veckorna innan, '
                'så de blir bättre ju längre agenten har körts.</p>')
    rows = "".join(
        f'<div class="in-alert"><div><span class="in-badge {_esc(a["level"])}">{_esc(a["level"])}</span></div>'
        f'<div>{_esc(a["title"])}<small>{_esc(a["detail"])}</small></div></div>'
        for a in alerts[:40]
    )
    return rows + ('<p class="in-note">Larmen räknas om vid varje körning. För att få dem som mejl, Discord, Teams eller '
                   'push-notis, se README (avsnittet Notiser).</p>')


def _cve_html(ctx) -> str:
    cves = ctx["cves"][:30]
    if not cves:
        return '<p class="empty">Ingen CVE-data ännu (fylls när CVE:er har hittats i artiklarna och berikats).</p>'
    rows = []
    for c in cves:
        tip = " | ".join(f"{l}: +{p}" for l, p in c["factors"])
        flags = []
        if c["kev"]:
            flags.append("KEV")
        if c["ransom"]:
            flags.append("ransomware")
        rows.append(
            f'<tr data-kev="{int(c["kev"])}" data-tech="{int(bool(c["tech"]))}">'
            f'<td><span class="in-score {c["level"]}" title="{_esc(tip)}">{c["score"]}</span>'
            f'<span class="in-bar" style="width:{c["score"]}%"></span></td>'
            f'<td><button class="in-link" data-ent="cve|{_esc(c["id"])}" type="button">{_esc(c["id"])}</button>'
            f'<div class="dim" style="font-size:0.74rem">{_esc(_shorten(c["summary"], 110))}</div></td>'
            f'<td class="num">{"%.1f" % c["cvss"] if c["cvss"] is not None else "–"}</td>'
            f'<td class="num">{"{:.0%}".format(c["epss"]) if c["epss"] is not None else "–"}</td>'
            f'<td>{_esc(", ".join(flags)) or "–"}</td>'
            f'<td>{_esc(", ".join(c["tech"][:2])) or "–"}</td>'
            f'<td class="num">{c["mentions"]}</td></tr>'
        )
    return (
        '<div class="in-filters"><span class="dim">Visa:</span>'
        '<button type="button" class="active" data-cvf="all">Alla</button>'
        '<button type="button" data-cvf="kev">Aktivt utnyttjade</button>'
        '<button type="button" data-cvf="tech">Berör min teknik</button></div>'
        '<table class="in-table" id="inCveTable"><tr><th>Risk</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Flaggor</th><th>Din teknik</th><th>Artiklar</th></tr>'
        + "".join(rows) + "</table>"
        '<p class="in-note">Poängen (0-100) summerar CVSS (max 25), EPSS (25), CISA KEV (25), ransomware-användning (10), '
        'omnämnanden i dina källor (8) och träff mot din teknikbevakning (7). Håll musen över poängen för uppdelning, '
        'klicka på CVE-numret för detaljer.</p>'
        "<script>(function(){var t=document.getElementById('inCveTable');if(!t)return;"
        "document.querySelectorAll('[data-cvf]').forEach(function(b){b.addEventListener('click',function(){"
        "var m=b.getAttribute('data-cvf');document.querySelectorAll('[data-cvf]').forEach(function(x){x.classList.toggle('active',x===b)});"
        "t.querySelectorAll('tr[data-kev]').forEach(function(r){r.style.display=(m==='all'||(m==='kev'&&r.dataset.kev==='1')||(m==='tech'&&r.dataset.tech==='1'))?'':'none'})})});})();</script>"
    )


def _sector_html(reports, today) -> str:
    cards = []
    for r in reports:
        nordic = "".join(f"<li>{_esc(v['victim'])} <small>({_esc(v['cc'])}, {v['day']}) – {_esc(v['group'])}</small></li>" for v in r["nordic"])
        arts = "".join(f'<li><a href="{_esc(a["link"])}" target="_blank" rel="noopener">{_esc(_shorten(a["title"], 100))}</a></li>' for a in r["articles"])
        cards.append(
            f'<div class="in-card"><h4>{_esc(r["name"])}</h4>'
            + "".join(f"<p>{_esc(l)}</p>" for l in r["lines"])
            + (f"<h5>Nordiska offer, 30 dagar</h5><ul>{nordic}</ul>" if nordic else "")
            + (f"<h5>Relevanta artiklar, 7 dagar</h5><ul>{arts}</ul>" if arts else "")
            + "</div>"
        )
    md = json.dumps(_report_markdown(reports, today), ensure_ascii=False).replace("</", "<\\/")
    return (
        f'<div class="in-filters"><button type="button" id="inRepDl">Ladda ner som Markdown</button>'
        f'<span class="dim">Regelbaserad veckosammanfattning, räknas om vid varje körning. Branscher justeras i intel.py (SECTOR_FOCUS).</span></div>'
        f'<div class="in-reports">{"".join(cards)}</div>'
        f"<script>(function(){{var md={md};var b=document.getElementById('inRepDl');if(!b)return;"
        f"b.addEventListener('click',function(){{var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([md],{{type:'text/markdown'}}));"
        f"a.download='sektorrapport-{today}.md';document.body.appendChild(a);a.click();a.remove();}});}})();</script>"
    )


_GRAPH_JS = r"""
(function () {
  var G = __GRAPH__;
  var box = document.getElementById("inGraph");
  if (!box) return;
  var COL = { group: "#ff9f1c", sector: "#4cc9f0", nordic: "#ff3b3b", country: "#8896ab", cve: "#c77dff" };
  function msg(t) { var d = document.createElement("div"); d.className = "in-gmsg"; d.textContent = t; box.appendChild(d); }
  if (!G.nodes.length) { msg("Ingen data att visa ännu."); return; }
  function loadScript(src) { return new Promise(function (res, rej) { var s = document.createElement("script"); s.src = src; s.onload = res; s.onerror = rej; document.head.appendChild(s); }); }
  var ready = window.d3 ? Promise.resolve() : loadScript("https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js");
  ready.then(function () {
    var W = box.clientWidth || 900, H = 520;
    var svg = d3.select(box).append("svg").attr("viewBox", "0 0 " + W + " " + H);
    var g = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.4, 4]).filter(function (e) { return (e.type !== "wheel" || e.ctrlKey || e.metaKey) && !e.button; }).on("zoom", function (e) { g.attr("transform", e.transform); }));
    var nodes = G.nodes.map(function (n) { return Object.assign({}, n); });
    var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });
    var links = G.links.map(function (l) { return { source: byId[l.s], target: byId[l.t], w: l.w }; }).filter(function (l) { return l.source && l.target; });
    var radius = function (n) { return n.type === "group" ? 8 + Math.sqrt(n.w) * 2.2 : 5 + Math.sqrt(n.w) * 1.2; };
    var sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).distance(function (l) { return 55 + 40 / (1 + l.w); }).strength(0.5))
      .force("charge", d3.forceManyBody().strength(-260))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("collide", d3.forceCollide().radius(function (n) { return radius(n) + 8; }));
    var link = g.append("g").selectAll("line").data(links).enter().append("line").attr("stroke", "#1f6fd0").attr("stroke-opacity", 0.45).attr("stroke-width", function (l) { return Math.min(4, 0.8 + Math.sqrt(l.w) * 0.5); });
    var node = g.append("g").selectAll("g").data(nodes).enter().append("g").style("cursor", "pointer")
      .call(d3.drag().on("start", function (e, d) { if (!e.active) sim.alphaTarget(0.25).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", function (e, d) { d.fx = e.x; d.fy = e.y; })
        .on("end", function (e, d) { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
    node.append("circle").attr("r", radius).attr("fill", function (d) { return COL[d.type]; }).attr("fill-opacity", 0.85).attr("stroke", "#fff").attr("stroke-opacity", 0.5);
    node.append("text").text(function (d) { return d.label; }).attr("dy", function (d) { return -radius(d) - 3; }).attr("text-anchor", "middle").attr("fill", "#cfe3ff").attr("font-size", 10).style("paint-order", "stroke").style("stroke", "#04070d").style("stroke-width", "3px").style("pointer-events", "none");
    var nb = {}; links.forEach(function (l) { (nb[l.source.id] = nb[l.source.id] || {})[l.target.id] = 1; (nb[l.target.id] = nb[l.target.id] || {})[l.source.id] = 1; });
    node.on("mouseover", function (e, d) {
      node.style("opacity", function (n) { return n.id === d.id || (nb[d.id] && nb[d.id][n.id]) ? 1 : 0.15; });
      link.style("opacity", function (l) { return l.source.id === d.id || l.target.id === d.id ? 1 : 0.05; });
    }).on("mouseout", function () { node.style("opacity", 1); link.style("opacity", 1); })
      .on("click", function (e, d) {
        var t = { group: "group", sector: "sector", nordic: "country", country: "country", cve: "cve" }[d.type], name = d.id.slice(2);
        if (window.ctiOpenEntity) window.ctiOpenEntity(t, name);
      });
    sim.on("tick", function () {
      link.attr("x1", function (l) { return l.source.x; }).attr("y1", function (l) { return l.source.y; }).attr("x2", function (l) { return l.target.x; }).attr("y2", function (l) { return l.target.y; });
      node.attr("transform", function (d) { d.x = Math.max(12, Math.min(W - 12, d.x)); d.y = Math.max(12, Math.min(H - 12, d.y)); return "translate(" + d.x + "," + d.y + ")"; });
    });
  }).catch(function () { msg("Grafen kunde inte laddas (D3 via CDN). Resten av panelen fungerar som vanligt."); });
})();
"""

_ENTITY_JS = r"""
(function () {
  var E = __ENT__;
  var input = document.getElementById("inEntInput"), out = document.getElementById("inEntOut"), dl = document.getElementById("inEntList");
  if (!input) return;
  var TYPE = { group: "Grupp", cve: "CVE", sector: "Bransch", country: "Land" };
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  var opts = "";
  Object.keys(E).forEach(function (t) { Object.keys(E[t]).forEach(function (n) { opts += '<option value="' + esc(n) + '">' + TYPE[t] + "</option>"; }); });
  dl.innerHTML = opts;
  function chip(e, label) { return '<button class="in-link" type="button" data-ent="' + esc(e[0]) + "|" + esc(e[1]) + '">' + esc(label) + "</button>"; }
  function render(x) {
    var h = '<div style="font-size:1.2rem;font-weight:600">' + esc(x.name) + ' <span class="in-badge Info">' + esc(x.sub) + "</span></div>";
    h += '<div class="in-kpis">' + x.kpis.map(function (k) { return '<div class="in-kpi' + (k[2] ? " alert" : "") + '"><b>' + esc(k[1]) + "</b><span>" + esc(k[0]) + "</span></div>"; }).join("") + "</div>";
    if (x.note) h += '<p class="dim" style="font-size:0.82rem;white-space:normal">' + esc(x.note) + "</p>";
    if (x.spark) { var mx = Math.max.apply(null, x.spark.concat([1])); h += '<div class="dim" style="font-size:0.72rem">Offer per vecka, 12 veckor</div><div class="in-spark">' + x.spark.map(function (v) { return '<i title="' + v + '" style="height:' + Math.max(4, v / mx * 100) + '%"></i>'; }).join("") + "</div>"; }
    h += '<div class="in-cols">';
    (x.bars || []).forEach(function (b) {
      if (!b.pairs.length) return;
      var m = Math.max.apply(null, b.pairs.map(function (p) { return p[1]; }).concat([1]));
      h += "<div><h5 class=\"dim\" style=\"margin:0 0 0.3rem;font-size:0.72rem;text-transform:uppercase\">" + esc(b.title) + '</h5><div class="in-bars">' + b.pairs.map(function (p) {
        return '<div class="r"><span class="lab">' + (p[2] ? chip(p[2], p[0]) : esc(p[0])) + '</span><span><span class="in-bar" style="width:' + Math.max(3, p[1] / m * 100) + '%"></span></span><span class="v">' + p[1] + "</span></div>";
      }).join("") + "</div></div>";
    });
    (x.lists || []).forEach(function (l) {
      if (!l.items.length) return;
      h += "<div><h5 class=\"dim\" style=\"margin:0 0 0.3rem;font-size:0.72rem;text-transform:uppercase\">" + esc(l.title) + '</h5><ul class="in-list">' + l.items.map(function (i) {
        var t = i.e ? chip(i.e, i.t) : (i.u ? '<a href="' + esc(i.u) + '" target="_blank" rel="noopener">' + esc(i.t) + "</a>" : esc(i.t));
        return "<li>" + t + (i.d ? " <small>" + esc(i.d) + "</small>" : "") + "</li>";
      }).join("") + "</ul></div>";
    });
    out.innerHTML = h + "</div>";
  }
  function find(name) {
    var q = name.trim().toLowerCase(), hit = null;
    ["group", "cve", "sector", "country"].forEach(function (t) { Object.keys(E[t]).forEach(function (n) { if (!hit && n.toLowerCase() === q) hit = [t, n]; }); });
    if (!hit && q.length >= 2) ["group", "cve", "sector", "country"].forEach(function (t) { Object.keys(E[t]).forEach(function (n) { if (!hit && n.toLowerCase().indexOf(q) >= 0) hit = [t, n]; }); });
    return hit;
  }
  window.ctiOpenEntity = function (t, n) {
    if (!E[t] || !E[t][n]) return;
    input.value = n; render(E[t][n]);
    var sec = document.getElementById("sec-entity");
    if (sec) { var d = sec.closest("details") || sec.querySelector("details"); if (d) d.open = true; sec.scrollIntoView({ behavior: "smooth", block: "start" }); }
  };
  input.addEventListener("change", function () { var h = find(input.value); if (h) render(E[h[0]][h[1]]); else out.innerHTML = '<p class="dim">Ingen träff. Prova ett gruppnamn, CVE-nummer, bransch eller landskod.</p>'; });
  input.addEventListener("keydown", function (e) { if (e.key === "Enter") input.dispatchEvent(new Event("change")); });
  document.addEventListener("click", function (e) { var b = e.target.closest("[data-ent]"); if (b) { var p = b.getAttribute("data-ent").split("|"); window.ctiOpenEntity(p[0], p.slice(1).join("|")); } });
  var first = Object.keys(E.group)[0]; if (first) render(E.group[first]);
})();
"""


def _json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str).replace("</", "<\\/")


def build_intel_blocks(db_path: str = DB_PATH) -> dict:
    """Returnerar {'alerts','sectorrep','cvescore','graph','entity'} -> HTML. Delar som misslyckas blir tomma meddelanden."""
    ctx = shared_context(db_path)
    blocks = {}

    def safe(key, fn):
        try:
            blocks[key] = fn()
        except Exception as e:  # ett fel i en sektion får inte stoppa panelen
            print(f"    Intel-sektionen '{key}' kunde inte byggas: {e}")
            blocks[key] = '<p class="empty">Sektionen kunde inte byggas denna körning.</p>'

    safe("alerts", lambda: _alerts_html(compute_alerts(db_path, ctx)))
    safe("sectorrep", lambda: _sector_html(build_sector_reports(ctx), ctx["today"]))
    safe("cvescore", lambda: _cve_html(ctx))
    safe("graph", lambda: (
        '<div class="in-graph" id="inGraph"><div class="in-legend">'
        '<span><i style="background:#ff9f1c"></i>grupp</span><span><i style="background:#4cc9f0"></i>bransch</span>'
        '<span><i style="background:#ff3b3b"></i>nordiskt land</span><span><i style="background:#8896ab"></i>övrigt land</span>'
        '<span><i style="background:#c77dff"></i>CVE</span></div></div>'
        '<p class="in-note">Visar de 12 mest aktiva grupperna senaste 90 dagarna, deras vanligaste branscher och länder samt '
        'sårbarheter som nämns tillsammans med gruppen i artiklar. Håll musen över en nod för att markera kopplingar, dra för att flytta, '
        'klicka för detaljer. Ctrl + scrollhjul zoomar.</p><script>' + _GRAPH_JS.replace("__GRAPH__", _json(build_graph(ctx))) + "</script>"))
    safe("entity", lambda: (
        '<div class="in-ent-head"><input id="inEntInput" list="inEntList" placeholder="Sök grupp, CVE, bransch eller land (t.ex. Qilin, CVE-2024-3400, SE)" autocomplete="off">'
        '<datalist id="inEntList"></datalist></div><div id="inEntOut"></div><script>'
        + _ENTITY_JS.replace("__ENT__", _json(build_entities(ctx, db_path))) + "</script>"))
    # Funktioner från fas 1-6 (egna moduler, alla fristående och valfria)
    safe("profile", lambda: __import__("org_profile").build_profile_html(ctx, db_path))
    safe("surface", lambda: __import__("attack_surface").build_surface_html(db_path))
    safe("lookalike", lambda: __import__("lookalike").build_lookalike_html(db_path))
    safe("hunting", lambda: __import__("hunting").build_hunting_html(db_path))
    safe("campaigns", lambda: __import__("campaigns").build_campaigns_html(db_path))
    safe("reports", lambda: __import__("reports").build_reports_html(ctx, db_path))
    safe("iocscore", lambda: __import__("ioc_confidence").build_ioc_confidence_html(db_path))
    safe("lookups", lambda: __import__("lookups").build_lookups_html(db_path))
    return blocks


def extra_css() -> str:
    """CSS för alla extra moduler, för injektion i generate_report."""
    css = ""
    for mod, const in (("org_profile", "PROFILE_CSS"), ("attack_surface", "SURFACE_CSS"), ("lookalike", "LOOKALIKE_CSS"),
                       ("hunting", "HUNTING_CSS"), ("campaigns", "CAMPAIGN_CSS"), ("reports", "REPORTS_CSS"),
                       ("ioc_confidence", "IOC_CONF_CSS"), ("lookups", "LOOKUPS_CSS")):
        try:
            css += getattr(__import__(mod), const)
        except Exception:
            pass
    return css


if __name__ == "__main__":
    c = load_context()
    for a in compute_alerts(ctx=c):
        print(f"[{a['level']}] {a['title']} – {a['detail']}")
