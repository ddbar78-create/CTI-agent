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
from storage import init_db, get_conn, save_article, save_iocs, recent_iocs
from abuse_ch import run_threatfox


def run_once():
    init_db()
    total_new_articles = 0
    total_new_iocs = 0

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

                # Extrahera IOCs ur titel + sammanfattning
                iocs = extract_iocs(f"{title}\n{summary}")
                if iocs:
                    save_iocs(conn, article_id, iocs)
                    count = sum(len(v) for v in iocs.values())
                    total_new_iocs += count
                    print(f"    Ny artikel: {title[:70]}  ({count} IOCs)")

    # Strukturerad, källbekräftad IOC-data från abuse.ch ThreatFox
    run_threatfox(days=1)

    print(f"\n=== Klart: {total_new_articles} nya artiklar, "
          f"{total_new_iocs} nya IOCs (via RSS) ===\n")

    print("Senaste IOCs i databasen:")
    for ioc_type, value, art_title, link in recent_iocs(limit=15):
        print(f"  [{ioc_type}] {value}  <- {art_title[:50]} ({link})")


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
