"""
Bygger en kort, läsbar sammanfattning av vad som hänt senaste dygnet.
Helt deterministisk — bygger meningar från siffror och mallar, ingen LLM
eller nyckel behövs. Om du senare aktiverar ANTHROPIC_API_KEY kan den
här modulen bytas ut mot en riktig LLM-skriven briefing, men det är ett
separat steg (se llm_extract.py).
"""

import sqlite3

from storage import DB_PATH
from attack_mapping import parse_family_from_value
from sector_watch import is_nordic_country


def _one(conn, query, params=()):
    row = conn.execute(query, params).fetchone()
    return row[0] if row and row[0] is not None else 0


def _all(conn, query, params=()):
    cur = conn.execute(query, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def build_briefing(db_path: str = DB_PATH, window: str = "-1 day") -> dict:
    """
    Returnerar en dict med både råa siffror (för ev. vidare bruk) och en
    färdig lista med sammanfattningsrader (strings) redo att visas.
    """
    conn = sqlite3.connect(db_path)

    new_articles = _one(
        conn,
        """
        SELECT COUNT(*) FROM articles
        WHERE feed != 'ransomware.live' AND feed NOT LIKE 'ThreatFox%'
          AND fetched_at >= datetime('now', ?)
        """,
        (window,),
    )

    threatfox_values = _all(
        conn,
        """
        SELECT iocs.value FROM iocs
        JOIN articles ON articles.id = iocs.article_id
        WHERE articles.feed LIKE 'ThreatFox%' AND articles.fetched_at >= datetime('now', ?)
        """,
        (window,),
    )
    new_threatfox = len(threatfox_values)
    family_counts: dict = {}
    for row in threatfox_values:
        fam = parse_family_from_value(row["value"])
        if fam:
            family_counts[fam] = family_counts.get(fam, 0) + 1
    top_families = sorted(family_counts.items(), key=lambda x: -x[1])[:3]

    new_victims = _all(
        conn,
        """
        SELECT group_name, victim, country, sector FROM ransomware_victims
        WHERE first_seen >= datetime('now', ?)
        ORDER BY id DESC
        """,
        (window,),
    )
    nordic_victims = [v for v in new_victims if is_nordic_country(v["country"])]

    urgent_cves = _all(
        conn,
        """
        SELECT cve_id, cvss, epss, kev FROM cve_enrichment
        WHERE checked_at >= datetime('now', ?) AND (kev = 1 OR epss >= 0.5)
        ORDER BY kev DESC, epss DESC
        """,
        (window,),
    )

    new_young_domains = _all(
        conn,
        """
        SELECT domain, age_days FROM domain_age
        WHERE checked_at >= datetime('now', ?) AND age_days < 30
        ORDER BY age_days ASC
        """,
        (window,),
    )

    new_watch_hits = _all(
        conn,
        """
        SELECT entry, kind, detail FROM watchlist_hits
        WHERE first_seen >= datetime('now', ?)
        ORDER BY id DESC
        """,
        (window,),
    )

    conn.close()

    # --- Bygg läsbara rader ---
    lines = []

    collection_bits = []
    if new_articles:
        collection_bits.append(f"{new_articles} nya artiklar")
    if new_threatfox:
        fam_str = ", ".join(f"{f} ({c})" for f, c in top_families)
        collection_bits.append(f"{new_threatfox} nya ThreatFox-IOCs" + (f" (mest: {fam_str})" if fam_str else ""))
    if collection_bits:
        lines.append("📥 " + " och ".join(collection_bits) + " samlades in.")
    else:
        lines.append("📥 Inga nya artiklar eller ThreatFox-IOCs senaste dygnet.")

    if new_watch_hits:
        entries = sorted({h["entry"] for h in new_watch_hits})
        lines.append(
            f"🚨 {len(new_watch_hits)} nya träffar på bevakningslistan: {', '.join(entries)}."
        )

    if urgent_cves:
        cve_list = ", ".join(c["cve_id"] for c in urgent_cves[:5])
        lines.append(f"🔴 {len(urgent_cves)} akuta CVE:er (KEV eller hög EPSS): {cve_list}.")

    if new_victims:
        nordic_note = f", varav {len(nordic_victims)} i Norden" if nordic_victims else ""
        examples = ", ".join(f"{v['victim']} ({v['country']})" for v in new_victims[:3])
        lines.append(f"🔴 {len(new_victims)} nya ransomware-offer{nordic_note}: {examples}.")
    else:
        lines.append("🟢 Inga nya ransomware-offer rapporterade senaste dygnet.")

    if new_young_domains:
        dom_list = ", ".join(f"{d['domain']} ({d['age_days']}d)" for d in new_young_domains[:3])
        lines.append(f"🟡 {len(new_young_domains)} nyregistrerade domäner (<30 dagar) flaggade: {dom_list}.")

    return {
        "lines": lines,
        "new_articles": new_articles,
        "new_threatfox": new_threatfox,
        "new_victims": len(new_victims),
        "nordic_victims": len(nordic_victims),
        "urgent_cves": len(urgent_cves),
        "new_watch_hits": len(new_watch_hits),
        "new_young_domains": len(new_young_domains),
    }
