"""
Hämtar vad ransomware-grupper själva offentliggör — offeraviseringar från
deras egna läcksidor — via det öppna, gratis API:et ransomware.live.

Det här är den säkra motsvarigheten till att själv övervaka hotaktörers
Telegram-/läckkanaler: samma information (vilket offer, vilken grupp,
vilket datum, vilken sektor/land), men insamlad och sanerad av
säkerhetsforskare istället för att du behöver ha en direkt koppling till
utpressningskanalerna själv.

API-dokumentation: https://www.ransomware.live/apidocs
Ingen API-nyckel krävs för grundläggande, icke-kommersiell användning.
"""

import sys

import requests

from storage import get_conn, save_article, save_iocs
from extract import extract_iocs

API_BASE = "https://api.ransomware.live/v2"


def fetch_recent_victims() -> list:
    """Hämtar senast offentliggjorda ransomware-offer."""
    try:
        resp = requests.get(
            f"{API_BASE}/recentvictims",
            timeout=30,
            headers={"User-Agent": "cti-agent/1.0 (personal, non-commercial)"},
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"    Fel vid ransomware.live-anrop: {e}", file=sys.stderr)
        return []


def run_ransomware_live() -> list:
    """Hämtar, sparar och (om möjligt) extraherar IOCs ur ransomware-offeraviseringar.
    Returnerar en lista av dicts för nya offer: {"group", "victim", "country"}."""
    print("[+] Hämtar: ransomware.live (offeraviseringar) ...")
    victims = fetch_recent_victims()
    if not victims:
        print("    Inga nya offeraviseringar.")
        return []

    new_victims = []
    with get_conn() as conn:
        for v in victims:
            victim_name = v.get("victim", "Okänt offer")
            group = v.get("group", "Okänd grupp")
            attack_date = v.get("attackdate", "")
            country = v.get("country", "")
            sector = v.get("activity") or v.get("sector") or ""

            # Ett unikt "länk"-värde krävs för dedupe — victim+grupp+datum
            # räcker för att identifiera en unik avisering.
            link = f"ransomware.live/{group}/{victim_name}/{attack_date}"
            title = f"{group}: {victim_name} ({country})"
            summary = (
                f"Grupp: {group}\nOffer: {victim_name}\nLand: {country}\n"
                f"Sektor: {sector}\nDatum: {attack_date}"
            )

            article_id = save_article(
                conn,
                feed="ransomware.live",
                title=title,
                link=link,
                published=attack_date,
                summary=summary,
            )
            if article_id is None:
                continue  # redan sedd tidigare

            new_victims.append({"group": group, "victim": victim_name, "country": country})

            # Extrahera ev. domäner/URL:er om sådana nämns i datan
            iocs = extract_iocs(summary)
            if iocs:
                save_iocs(conn, article_id, iocs)

            print(f"    Ny avisering: {group} -> {victim_name} ({country})")

    if new_victims:
        print(f"    ransomware.live: {len(new_victims)} nya offeraviseringar")
    else:
        print("    ransomware.live: inga nya aviseringar.")

    return new_victims


if __name__ == "__main__":
    run_ransomware_live()
