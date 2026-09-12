"""
Hämtar strukturerade, verifierade IOCs från abuse.ch ThreatFox.
Till skillnad från RSS+regex-extraktionen i agent.py är det här riktig,
källbekräftad hotdata — varje post är redan taggad med malware-familj
och en confidence-nivå, satt av abuse.ch:s analytiker/community.

API-dokumentation: https://threatfox.abuse.ch/api/
Ingen API-nyckel krävs för att läsa ut senaste IOCs.
"""

import os
import time
import sys

import requests

from storage import get_conn, save_article, save_iocs

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox(days: int = 1) -> list:
    """Hämtar IOCs från de senaste N dagarna. Returnerar en lista av dicts."""
    auth_key = os.environ.get("THREATFOX_AUTH_KEY")
    if not auth_key:
        print(
            "    Ingen THREATFOX_AUTH_KEY satt — hoppar över ThreatFox. "
            "Skaffa en gratis nyckel på https://auth.abuse.ch/",
            file=sys.stderr,
        )
        return []

    try:
        resp = requests.post(
            THREATFOX_API,
            json={"query": "get_iocs", "days": days},
            headers={"Auth-Key": auth_key},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"    Fel vid ThreatFox-anrop: {e}", file=sys.stderr)
        return []

    if data.get("query_status") != "ok":
        print(f"    ThreatFox svarade: {data.get('query_status')}", file=sys.stderr)
        return []

    return data.get("data", [])


def run_threatfox(days: int = 1):
    """Hämtar, grupperar och sparar ThreatFox-IOCs i samma databas som RSS-agenten."""
    print("[+] Hämtar: ThreatFox (abuse.ch) ...")
    entries = fetch_threatfox(days=days)
    if not entries:
        print("    Inga nya IOCs från ThreatFox.")
        return

    with get_conn() as conn:
        # En syntetisk "artikel" representerar denna körnings ThreatFox-hämtning,
        # så att IOCs kan länkas i samma tabellstruktur som RSS-artiklar.
        link = f"threatfox-pull-{int(time.time())}"
        article_id = save_article(
            conn,
            feed="ThreatFox (abuse.ch)",
            title=f"ThreatFox IOC-hämtning ({len(entries)} poster)",
            link=link,
            published="",
            summary="",
        )
        if article_id is None:
            return

        grouped = {}
        for entry in entries:
            ioc_type = entry.get("ioc_type", "unknown")
            value = entry.get("ioc", "")
            malware = entry.get("malware_printable", "okänd")
            confidence = entry.get("confidence_level", "?")
            # Vi berikar värdet med kontext direkt i strängen, så att det syns
            # även i den enkla text-baserade vyn (t.ex. i GitHub Actions-loggen).
            enriched = f"{value}  [{malware}, confidence {confidence}]"
            grouped.setdefault(ioc_type, set()).add(enriched)

        save_iocs(conn, article_id, grouped)
        total = sum(len(v) for v in grouped.values())
        print(f"    Sparade {total} ThreatFox-IOCs (malware-familjer inkluderade)")


if __name__ == "__main__":
    run_threatfox()
