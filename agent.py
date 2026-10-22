"""
CTI-agent: hämtar RSS-flöden, extraherar IOCs, lagrar i SQLite,
och skriver ut en kort sammanfattning.

Kör:
    python3 agent.py            # kör en gång
    python3 agent.py --loop 3600  # kör var 3600:e sekund (loop-läge)
"""

import argparse
import time
import sys

import feedparser
import requests

from feeds import FEEDS
from extract import extract_iocs
from storage import (
    init_db, get_conn, save_article, save_iocs, recent_iocs,
    save_llm_enrichment, record_daily_stats, save_full_text,
)
from abuse_ch import run_threatfox
from llm_extract import enrich_article
from telegram_scan import run_telegram
from telegram_channels import CHANNELS as TELEGRAM_CHANNELS
from ransomware_live import run_ransomware_live
from ransomlook import run_ransomlook
from source_catalog import run_source_catalog
from notify import notify
from generate_report import generate_report
from retention import prune_old_data
from shodan_lookup import run_shodan_enrichment
from cve_priority import run_cve_enrichment
from article_crawler import crawl_article, MAX_CRAWLS_PER_RUN, DELAY_BETWEEN_REQUESTS
from crt_sh import run_crtsh_enrichment
from domain_age import run_domain_age_check
from more_sources import run_more_sources
from tech_watch import match_kev_entries
from run_status import tracked, record
from export_feeds import export_all
from patch_stats import run_patch_stats



_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)


def _fetch_feed(url: str):
    """Hämtar RSS med webbläsar-UA (t.ex. cisa.gov blockerar standard-agenten)."""
    try:
        r = requests.get(
            url, timeout=30,
            headers={"User-Agent": _BROWSER_UA,
                     "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"},
        )
        if r.ok and r.content:
            parsed = feedparser.parse(r.content)
            if parsed.entries:
                return parsed
    except requests.RequestException:
        pass
    return feedparser.parse(url, agent=_BROWSER_UA)


def run_once():
    init_db()
    total_new_articles = 0
    total_new_iocs = 0
    high_severity_hits = []  # (titel, aktör, allvarlighet) för LLM-flaggade artiklar
    crawl_count = 0  # begränsar antal fullständiga sidhämtningar denna körning
    feed_status = []  # (namn, ok, nya, fel) — sparas när databastransaktionen stängts

    with get_conn() as conn:
        for feed in FEEDS:
            print(f"[+] Hämtar: {feed['name']} ...")
            try:
                parsed = _fetch_feed(feed["url"])
            except Exception as e:
                print(f"    Fel vid hämtning: {e}", file=sys.stderr)
                feed_status.append((feed["name"], 0, 0, str(e)))
                continue

            if parsed.bozo and not parsed.entries:
                print(f"    Kunde inte tolka flödet ({feed['url']})", file=sys.stderr)
                feed_status.append((feed["name"], 0, 0, "kunde inte tolka flödet"))
                continue

            new_in_feed = 0
            for entry in parsed.entries:
                title = entry.get("title", "")
                link = entry.get("link", "")
                published = entry.get("published", "")
                summary = entry.get("summary", "") or entry.get("description", "")

                article_id = save_article(
                    conn, feed["name"], title, link, published, summary
                )
                if article_id is None:
                    continue  # redan sedd tidigare

                total_new_articles += 1
                new_in_feed += 1

                # Hämta fullständig artikeltext + utvalda referenslänkar
                combined_text = f"{title}\n{summary}"
                if crawl_count < MAX_CRAWLS_PER_RUN and link:
                    full_text = crawl_article(link)
                    if full_text:
                        save_full_text(conn, article_id, full_text)
                        combined_text = f"{title}\n{full_text}"
                    crawl_count += 1
                    time.sleep(DELAY_BETWEEN_REQUESTS)

                # Regex-baserade IOCs (snabbt, gratis, men brusigt)
                iocs = extract_iocs(combined_text)
                if iocs:
                    save_iocs(conn, article_id, iocs)
                    count = sum(len(v) for v in iocs.values())
                    total_new_iocs += count
                    print(f"    Ny artikel: {title[:70]}  ({count} IOCs)")
                else:
                    print(f"    Ny artikel: {title[:70]}")

                # LLM-baserad kontext (hotaktör, TTPs, sektor, allvarlighet)
                enrichment = enrich_article(title, combined_text)
                if enrichment:
                    save_llm_enrichment(conn, article_id, enrichment)
                    if enrichment.get("is_relevant"):
                        actor = enrichment.get("threat_actor") or "okänd aktör"
                        severity = enrichment.get("severity", "okänd")
                        print(f"      -> LLM: {actor}, allvarlighet: {severity}")
                        if severity in ("high", "critical"):
                            high_severity_hits.append((title[:80], actor, severity))

            feed_status.append((feed["name"], 1, new_in_feed, ""))

    for name, ok, n, err in feed_status:
        record(name, ok, n, err)

    # Strukturerad, källbekräftad IOC-data från abuse.ch ThreatFox
    threatfox_count = tracked("ThreatFox", run_threatfox, days=1, default=0)

    # Publika Telegram-kanaler (se telegram_channels.py för konfiguration)
    telegram_count = tracked("Telegram", run_telegram, TELEGRAM_CHANNELS, default=0)

    # Vad ransomware-grupper själva offentliggör om sina offer
    new_victims = tracked("ransomware.live", run_ransomware_live, default=[])

    # Extra ransomware-källa (komplement till ransomware.live) och dygnsstatistik över deepdarkCTI
    tracked("RansomLook", run_ransomlook, default=0)
    tracked("Källkatalog", run_source_catalog, default=0)

    # Extra källor: CISA KEV, URLhaus, Feodo Tracker och fler RSS-flöden.
    # Körs före berikningen så att nya IP:er och CVE:er hinner slås upp direkt.
    try:
        more = run_more_sources()
    except Exception as e:  # sista skyddsnätet
        print(f"    Extra källor: oväntat fel ({e})", file=sys.stderr)
        more = {"kev": [], "urlhaus": 0, "feodo": 0, "rss": 0, "mbazaar": 0, "otx": 0}

    # Berika insamlade IP-adresser med öppna portar/CVE:er (Shodan)
    tracked("Shodan", run_shodan_enrichment, default=None)

    # Prioritera CVE:er med EPSS/KEV-data (Shodan CVEDB, gratis)
    urgent_cves = tracked("CVE-prioritering", run_cve_enrichment, default=[])

    # Hitta relaterad infrastruktur för domäner via Certificate Transparency
    tracked("crt.sh", run_crtsh_enrichment, default=0)

    # Kontrollera domänålder via RDAP — flaggar nyregistrerade domäner
    new_registered_domains = tracked("RDAP domänålder", run_domain_age_check, default=[])

    # Patchstatistik för Windows och Linux (hämtas högst var 12:e timme)
    tracked("Patchstatistik", run_patch_stats, default=0)

    # Bevakningslistan är borttagen (watchlist.py behövs inte längre)
    new_watch_hits = []

    print(f"\n=== Klart: {total_new_articles} nya artiklar, "
          f"{total_new_iocs} nya IOCs (via RSS) ===\n")

    print("Senaste IOCs i databasen:")
    for ioc_type, value, art_title, link in recent_iocs(limit=15):
        print(f"  [{ioc_type}] {value}  <- {art_title[:50]} ({link})")

    # --- Bygg och skicka en sammanfattande notis, bara om något är värt att flagga ---
    summary_lines = []

    if new_watch_hits:
        summary_lines.append(f"🚨 {len(new_watch_hits)} nya träffar på din bevakningslista:")
        for h in new_watch_hits[:10]:
            if isinstance(h, dict):
                summary_lines.append(f"   • {h.get('entry', '?')} [{h.get('kind', '')}] {str(h.get('detail', ''))[:100]}")
            else:
                summary_lines.append(f"   • {h}")

    tech_hits = match_kev_entries(more["kev"])
    if tech_hits:
        summary_lines.append(f"🛡️ {len(tech_hits)} nya KEV-sårbarheter berör din teknik:")
        for t in tech_hits[:10]:
            ransom = " – används av ransomware" if t["ransomware"] else ""
            summary_lines.append(f"   • {t['tech']}: {t['cve_id']}{ransom}")

    if more["kev"]:
        summary_lines.append(f"🔴 {len(more['kev'])} nya aktivt utnyttjade sårbarheter (CISA KEV):")
        for k in more["kev"][:10]:
            ransom = " – används av ransomware" if k.get("ransomware") else ""
            summary_lines.append(f"   • {k['cve_id']}{ransom}")

    if urgent_cves:
        summary_lines.append(f"🔴 {len(urgent_cves)} akuta CVE:er (KEV eller EPSS ≥ 50%):")
        for c in urgent_cves[:10]:
            flag = "KEV" if c["kev"] else f"EPSS {c['epss']:.0%}"
            summary_lines.append(f"   • {c['cve_id']} ({flag})")

    if new_victims:
        summary_lines.append(f"🔴 {len(new_victims)} nya ransomware-offer:")
        for v in new_victims[:10]:
            summary_lines.append(f"   • {v['group']} → {v['victim']} ({v['country']})")

    if new_registered_domains:
        summary_lines.append(f"🟡 {len(new_registered_domains)} nyregistrerade domäner (<30 dagar):")
        for d in new_registered_domains[:10]:
            summary_lines.append(f"   • {d['domain']} ({d['age_days']} dagar)")

    if high_severity_hits:
        summary_lines.append(f"🟠 {len(high_severity_hits)} artiklar med hög/kritisk allvarlighet:")
        for title, actor, severity in high_severity_hits[:10]:
            summary_lines.append(f"   • [{severity}] {actor}: {title}")

    if threatfox_count:
        summary_lines.append(f"🔵 {threatfox_count} nya ThreatFox-IOCs (confidence ≥ 75)")

    if more["urlhaus"] or more["feodo"]:
        summary_lines.append(
            f"🔵 {more['urlhaus']} nya URLhaus-IOCs och {more['feodo']} nya botnet-C2-IP:er (Feodo)"
        )

    if more.get("mbazaar"):
        summary_lines.append(f"🔵 {more['mbazaar']} nya malware-hashar (MalwareBazaar)")

    if more.get("otx"):
        summary_lines.append(f"🔵 {more['otx']} nya kampanjer (AlienVault OTX)")

    if telegram_count:
        summary_lines.append(f"🔵 {telegram_count} nya Telegram-inlägg")

    notify(summary_lines)

    # Spara dagens siffror i den lilla, aldrig-rensade trendtabellen
    with get_conn() as conn:
        record_daily_stats(
            conn,
            new_articles=total_new_articles + more["rss"],
            new_iocs_regex=total_new_iocs,
            new_iocs_threatfox=threatfox_count,
            new_telegram=telegram_count,
            new_ransomware_victims=len(new_victims),
        )

    # Håll databasen hanterbar i storlek (se retention.py för policy)
    prune_old_data()

    # Exportera IOC:er som CSV, blocklistor och STIX 2.1 (mappen exports/)
    tracked("Export", lambda: export_all()["iocs.csv"], default=0)

    # Bygg om instrumentpanelen (index.html) med senaste datan
    generate_report()


def main():
    parser = argparse.ArgumentParser(description="Enkel CTI-insamlingsagent")
    parser.add_argument(
        "--loop", type=int, default=0,
        help="Kör kontinuerligt med N sekunders mellanrum (0 = kör en gång)"
    )
    args = parser.parse_args()

    if args.loop <= 0:
        run_once()
    else:
        print(f"Kör i loop-läge, var {args.loop}:e sekund. Avbryt med Ctrl+C.")
        while True:
            run_once()
            time.sleep(args.loop)


if __name__ == "__main__":
    main()
