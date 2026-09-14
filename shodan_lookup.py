"""
Berikar IP-adresser från dina insamlade IOCs med Shodan.

Har du satt SHODAN_API_KEY (GitHub Secret) används Shodans FULLSTÄNDIGA
Host-API — mer detaljerat: organisation, ISP, ASN, geografisk plats,
tjänstebannrar, utöver portar/CVE:er/hostnames.

Saknas nyckeln faller modulen automatiskt tillbaka på Shodan InternetDB
— gratis, ingen nyckel krävs, men mindre detaljerad data. Resten av
agenten fungerar likadant oavsett vilket läge som används.

Dokumentation:
  Fullständigt API: https://developer.shodan.io/api
  InternetDB (gratis): https://internetdb.shodan.io/
"""

import os
import sys
import time

import requests

from storage import get_conn, get_unenriched_ips, save_ip_enrichment

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
FULL_API_URL = "https://api.shodan.io/shodan/host/{ip}"

# Gratis InternetDB har ingen praktisk kreditgräns, men vi är ändå snälla
# mot den delade tjänsten. Fullständiga API:et kostar riktiga sökkrediter
# per uppslag, så där håller vi antalet lägre som standard (går att höja
# via SHODAN_MAX_LOOKUPS om din plan tillåter det).
INTERNETDB_MAX_LOOKUPS = 20
FULL_API_MAX_LOOKUPS = int(os.environ.get("SHODAN_MAX_LOOKUPS", "10"))
DELAY_BETWEEN_CALLS = 1.2  # Shodans API tillåter ~1 anrop/sekund


def lookup_ip_internetdb(ip: str) -> dict | None:
    """Gratis, nyckellöst uppslag via InternetDB."""
    try:
        resp = requests.get(INTERNETDB_URL.format(ip=ip), timeout=15)
    except requests.RequestException as e:
        print(f"    Fel vid InternetDB-uppslag av {ip}: {e}", file=sys.stderr)
        return None

    if resp.status_code == 404:
        return None  # IP:n finns inte i Shodans dataset — helt normalt

    if resp.status_code != 200:
        print(f"    InternetDB svarade {resp.status_code} för {ip}", file=sys.stderr)
        return None

    try:
        return resp.json()
    except ValueError:
        return None


def lookup_ip_full(ip: str, api_key: str) -> dict | None:
    """Detaljerat uppslag via ditt riktiga Shodan-konto (kostar sökkrediter)."""
    try:
        resp = requests.get(
            FULL_API_URL.format(ip=ip), params={"key": api_key}, timeout=20
        )
    except requests.RequestException as e:
        print(f"    Fel vid Shodan-uppslag av {ip}: {e}", file=sys.stderr)
        return None

    if resp.status_code == 404:
        return None  # ingen data för denna IP

    if resp.status_code == 401:
        print("    Shodan: ogiltig SHODAN_API_KEY eller slut på krediter",
              file=sys.stderr)
        return None

    if resp.status_code != 200:
        print(f"    Shodan svarade {resp.status_code} för {ip}", file=sys.stderr)
        return None

    try:
        return resp.json()
    except ValueError:
        return None


def _normalize_full_api_response(data: dict) -> dict:
    """Gör om det fullständiga API-svaret till samma form som InternetDB,
    plus lite extra kontext (org/land) instoppat i taggarna."""
    vulns_field = data.get("vulns")
    vulns = list(vulns_field.keys()) if isinstance(vulns_field, dict) else (vulns_field or [])

    tags = list(data.get("tags") or [])
    extra_context = ", ".join(
        filter(None, [data.get("org"), data.get("country_name")])
    )
    if extra_context:
        tags.append(extra_context)

    return {
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "vulns": vulns,
        "tags": tags,
    }


def run_shodan_enrichment() -> int:
    """
    Berikar nya, ännu ej uppslagna IP-adresser. Använder din riktiga
    Shodan-nyckel om SHODAN_API_KEY är satt, annars gratis InternetDB.
    Returnerar antal IP-adresser som faktiskt hade data.
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    limit = FULL_API_MAX_LOOKUPS if api_key else INTERNETDB_MAX_LOOKUPS

    ips = get_unenriched_ips(limit=limit)
    if not ips:
        return 0

    source_label = "Shodan (fullständigt API)" if api_key else "Shodan InternetDB (gratis)"
    print(f"[+] {source_label}: slår upp {len(ips)} nya IP-adresser ...")
    found_count = 0

    with get_conn() as conn:
        for ip in ips:
            if api_key:
                raw = lookup_ip_full(ip, api_key)
                normalized = _normalize_full_api_response(raw) if raw else None
            else:
                raw = lookup_ip_internetdb(ip)
                normalized = raw

            if normalized:
                save_ip_enrichment(
                    conn,
                    ip=ip,
                    ports=normalized.get("ports", []),
                    hostnames=normalized.get("hostnames", []),
                    vulns=normalized.get("vulns", []),
                    tags=normalized.get("tags", []),
                )
                found_count += 1
                vulns = normalized.get("vulns", [])
                if vulns:
                    print(f"    {ip}: {len(normalized.get('ports', []))} öppna portar, "
                          f"{len(vulns)} kända CVE:er")

            time.sleep(DELAY_BETWEEN_CALLS)

    print(f"    Shodan: {found_count}/{len(ips)} IP:er hade data")
    return found_count


if __name__ == "__main__":
    run_shodan_enrichment()
