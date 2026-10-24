"""
Din organisation: det som attackytan, look-alike-bevakningen och hotprofilen utgår från.

VIKTIGT: repot är publikt. Skriv bara in uppgifter som redan är offentliga
(domännamn, AS-nummer och IP-intervall som syns i BGP/RIPE, varumärkesnamn). Inga interna
adresser, inga personuppgifter, inga lösenord.

Förifyllt för Trafikverket (AS49272, offentliga prefix enligt BGP-data). Kontrollera listan mot
RIPE/bgp.he.net och justera. Lägg till fler domäner (t.ex. egna API-tjänster) i "domains".
Bevaka bara ytor ni har mandat att bevaka. Attackyte-modulen gör inga egna skanningar,
den slår bara upp vad Shodan InternetDB redan vet om en IP-adress.
"""

ORG = {
    "name": "Trafikverket",
    # Nyckel i SECTOR_FOCUS (intel.py) som hotprofilen utgår från
    "sector": "Transport och logistik",
    # Länder som räknas som "hemma" i hotprofilen (ISO-2)
    "countries": ["SE"],
    # Domäner att bevaka: attackyta (underdomäner, certifikat) och look-alikes
    "domains": ["trafikverket.se"],
    # Offentliga AS-nummer och IPv4-intervall. IPv6 skannas inte (Shodan InternetDB täcker bara IPv4).
    "asns": ["AS49272"],
    "ip_ranges": ["188.121.64.0/19", "192.176.229.0/24", "192.176.230.0/24"],
    # Varumärkesnamn som ska hittas i look-alike-domäner och artiklar
    "brands": ["trafikverket"],
    # Look-alike-domäner som du har kontrollerat och vet är legitima eller ofarliga
    "safe_domains": [],
}

# Hur många IP-adresser som slås upp per körning (hela intervallet roteras över flera körningar)
SURFACE_IPS_PER_RUN = 250
# Hur många look-alike-varianter som kontrolleras per körning
LOOKALIKES_PER_RUN = 150
