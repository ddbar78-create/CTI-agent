"""
Kontrollerar registreringsdatum för insamlade domäner via RDAP (den
moderna, HTTPS-baserade efterträdaren till WHOIS-protokollet). Helt
gratis, ingen nyckel krävs, och mycket pålitligare i molnmiljöer än
klassiskt WHOIS (som kräver råa socket-anrop på port 43).

Varför detta är värdefullt: en NYREGISTRERAD domän (några dagar eller
veckor gammal) är en av de starkaste enskilda varningssignalerna inom
phishing- och malware-kampanjer — legitima företag registrerar sällan
en domän och börjar använda den för produktion samma dag. Vi flaggar
domäner yngre än 30 dagar som extra misstänkta.

Använder rdap.org:s öppna bootstrap-tjänst, som automatiskt dirigerar
frågan till rätt registry oavsett toppdomän.
"""

import sys
import time
from datetime import datetime, timezone

import requests

from storage import get_conn, get_unenriched_domains_for_age, save_domain_age

RDAP_URL = "https://rdap.org/domain/{domain}"

MAX_LOOKUPS_PER_RUN = 15
DELAY_BETWEEN_CALLS = 1.0
REQUEST_TIMEOUT = 10
NEW_DOMAIN_THRESHOLD_DAYS = 30


def _parse_registration_date(rdap_data: dict):
    """RDAP-registries stavar händelsenamnet lite olika ('registration',
    'registered'), så vi kollar båda varianterna."""
    for event in rdap_data.get("events", []):
        action = (event.get("eventAction") or "").lower()
        if action in ("registration", "registered"):
            date_str = event.get("eventDate")
            if date_str:
                try:
                    return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except ValueError:
                    return None
    return None


def _extract_registrar(rdap_data: dict) -> str:
    for entity in rdap_data.get("entities", []):
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        return field[3]
    return ""


def lookup_domain_age(domain: str):
    """Returnerar (registrerings_datum, ålder_i_dagar, registrar) eller (None, None, None)."""
    try:
        resp = requests.get(RDAP_URL.format(domain=domain), timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        print(f"    Fel vid RDAP-uppslag av {domain}: {e}", file=sys.stderr)
        return None, None, None

    if resp.status_code == 404:
        return None, None, None  # domänen har ingen RDAP-post (ovanligt, men händer)

    if resp.status_code != 200:
        print(f"    RDAP svarade {resp.status_code} för {domain}", file=sys.stderr)
        return None, None, None

    try:
        data = resp.json()
    except ValueError:
        return None, None, None

    reg_date = _parse_registration_date(data)
    if reg_date is None:
        return None, None, None

    age_days = (datetime.now(timezone.utc) - reg_date).days
    registrar = _extract_registrar(data)
    return reg_date.strftime("%Y-%m-%d"), age_days, registrar


def run_domain_age_check() -> list:
    """
    Kontrollerar nya domäner. Returnerar en lista över domäner yngre än
    NEW_DOMAIN_THRESHOLD_DAYS dagar — dessa är extra värda att flagga.
    """
    domains = get_unenriched_domains_for_age(limit=MAX_LOOKUPS_PER_RUN)
    if not domains:
        return []

    print(f"[+] RDAP: kontrollerar domänålder för {len(domains)} domäner ...")
    new_domains = []

    with get_conn() as conn:
        for domain in domains:
            reg_date, age_days, registrar = lookup_domain_age(domain)
            if reg_date is not None:
                save_domain_age(conn, domain, reg_date, age_days, registrar)
                if age_days is not None and age_days < NEW_DOMAIN_THRESHOLD_DAYS:
                    new_domains.append({"domain": domain, "age_days": age_days, "registered": reg_date})
                    print(f"    ⚠ {domain}: bara {age_days} dagar gammal (registrerad {reg_date})")
            time.sleep(DELAY_BETWEEN_CALLS)

    print(f"    RDAP: {len(domains)} domäner kontrollerade, {len(new_domains)} nyregistrerade (<{NEW_DOMAIN_THRESHOLD_DAYS} dagar)")
    return new_domains


if __name__ == "__main__":
    run_domain_age_check()
