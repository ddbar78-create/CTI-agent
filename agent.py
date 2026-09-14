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

from feeds import FEEDS
from extract import extract_iocs
from storage import (
    init_db, get_conn, save_article, save_iocs, recent_iocs,
    save_llm_enrichment,
)
from abuse_ch import run_threatfox
from llm_extract import enrich_article
from telegram_scan import run_telegram
from telegram_channels import CHANNELS as TELEGRAM_CHANNELS
from ransomware_live import run_ransomware_live
from notify import notify
from generate_report import generate_report


def run_once():
    init_db()
    total_new_articles = 0
    total_new_iocs = 0
    high_severity_hits = []  # (titel, aktör, allvarlighet) för LLM-flaggade artiklar

    with get_conn() as conn:
        for feed in FEEDS:
            print(f"[+] Hämtar: {feed['name']} ...")
            try:
                parsed = feedparser.parse(feed["url"])
            except Exception as e:
                print(f"    Fel vid hämtning: {e}", file=sys.stderr)
                continue

            if parsed.bozo and not parsed.entries:
                print(f"    Kunde inte tolka flödet ({feed['url']})", file=sys.stderr)
                continue

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

                # Regex-baserade IOCs (snabbt, gratis, men brusigt)
                iocs = extract_iocs(f"{title}\n{summary}")
                if iocs:
                    save_iocs(conn, article_id, iocs)
                    count = sum(len(v) for v in iocs.values())
                    total_new_iocs += count
                    print(f"    Ny artikel: {title[:70]}  ({count} IOCs)")
                else:
                    print(f"    Ny artikel: {title[:70]}")

                # LLM-baserad kontext (hotaktör, TTPs, sektor, allvarlighet)
                enrichment = enrich_article(title, summary)
                if enrichment:
                    save_llm_enrichment(conn, article_id, enrichment)
                    if enrichment.get("is_relevant"):
                        actor = enrichment.get("threat_actor") or "okänd aktör"
                        severity = enrichment.get("severity", "okänd")
                        print(f"      -> LLM: {actor}, allvarlighet: {severity}")
                        if severity in ("high", "critical"):
                            high_severity_hits.append((title[:80], actor, severity))

    # Strukturerad, källbekräftad IOC-data från abuse.ch ThreatFox
    threatfox_count = run_threatfox(days=1)

    # Publika Telegram-kanaler (se telegram_channels.py för konfiguration)
    telegram_count = run_telegram(TELEGRAM_CHANNELS)

    # Vad ransomware-grupper själva offentliggör om sina offer
    new_victims = run_ransomware_live()

    print(f"\n=== Klart: {total_new_articles} nya artiklar, "
          f"{total_new_iocs} nya IOCs (via RSS) ===\n")

    print("Senaste IOCs i databasen:")
    for ioc_type, value, art_title, link in recent_iocs(limit=15):
        print(f"  [{ioc_type}] {value}  <- {art_title[:50]} ({link})")

    # --- Bygg och skicka en sammanfattande notis, bara om något är värt att flagga ---
    summary_lines = []

    if new_victims:
        summary_lines.append(f"🔴 {len(new_victims)} nya ransomware-offer:")
        for v in new_victims[:10]:
            summary_lines.append(f"   • {v['group']} → {v['victim']} ({v['country']})")

    if high_severity_hits:
        summary_lines.append(f"🟠 {len(high_severity_hits)} artiklar med hög/kritisk allvarlighet:")
        for title, actor, severity in high_severity_hits[:10]:
            summary_lines.append(f"   • [{severity}] {actor}: {title}")

    if threatfox_count:
        summary_lines.append(f"🔵 {threatfox_count} nya ThreatFox-IOCs (confidence ≥ 75)")

    if telegram_count:
        summary_lines.append(f"🔵 {telegram_count} nya Telegram-inlägg")

    notify(summary_lines)

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
