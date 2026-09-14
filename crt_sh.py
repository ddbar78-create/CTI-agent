"""
Hittar relaterad infrastruktur för dina insamlade domäner via crt.sh —
en sökbar spegel av Certificate Transparency-loggar. Helt gratis, ingen
nyckel krävs.

Idén: när en angripare skaffar ett SSL-certifikat för en domän listas
det offentligt i CT-loggarna. Om samma certifikat (eller samma
certifikatutfärdare/mönster) täcker flera subdomäner avslöjar det ofta
mer av infrastrukturen bakom en kampanj — t.ex. att "evil1.example.com"
och "evil2.example.com" hör ihop, även om bara den ena dykt upp i dina
andra källor än.

Dokumentation: https://sslmate.com/certspotter/api/ (crt.sh saknar
formell dokumentation men dess JSON-endpoint är väletablerad och stabil
i praktiken, om än ibland långsam vid hög belastning).
"""

import sys
import time

import requests

from storage import get_conn, get_unenriched_domains, save_domain_enrichment

CRTSH_URL = "https://crt.sh/"

# crt.sh är en gratis, delad community-tjänst som ibland är långsam under
# hög belastning — vi håller volymen låg och pausen längre än för de
# andra källorna som en artighet.
MAX_LOOKUPS_PER_RUN = 15
DELAY_BETWEEN_CALLS = 2.0
REQUEST_TIMEOUT = 30


def lookup_domain(domain: str) -> list:
    """Returnerar en lista relaterade domännamn funna via delade certifikat."""
    try:
        resp = requests.get(
            CRTSH_URL, params={"q": domain, "output": "json"}, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"    Fel vid crt.sh-uppslag av {domain}: {e}", file=sys.stderr)
        return []

    try:
        data = resp.json()
    except ValueError:
        # crt.sh returnerar ibland trasig/tom respons vid hög belastning —
        # inte ett fel i vår kod, bara att köra vidare till nästa domän.
        return []

    related = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and name != domain.lower() and not name.startswith("*."):
                related.add(name)

    return sorted(related)[:20]


def run_crtsh_enrichment() -> int:
    """Berikar nya domäner. Returnerar antal domäner som hade relaterad infrastruktur."""
    domains = get_unenriched_domains(limit=MAX_LOOKUPS_PER_RUN)
    if not domains:
        return 0

    print(f"[+] crt.sh: söker relaterad infrastruktur för {len(domains)} domäner ...")
    found_count = 0

    with get_conn() as conn:
        for domain in domains:
            related = lookup_domain(domain)
            if related:
                save_domain_enrichment(conn, domain, related)
                found_count += 1
                print(f"    {domain}: {len(related)} relaterade domäner hittade")
            time.sleep(DELAY_BETWEEN_CALLS)

    print(f"    crt.sh: {found_count}/{len(domains)} domäner hade relaterad infrastruktur")
    return found_count


if __name__ == "__main__":
    run_crtsh_enrichment()
