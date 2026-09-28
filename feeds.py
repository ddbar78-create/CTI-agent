"""
Lista över OSINT/CTI-källor (RSS-flöden).
Lägg till egna feeds här — t.ex. leverantörsbloggar, CERT-flöden,
eller din branschs ISAC om de erbjuder RSS.

OBS: namnen på de nordiska källorna används även av sector_watch.py för att
automatiskt märka artiklar som "Norden" — ändrar du ett namn här, ändra det
även i NORDIC_FEED_NAMES i sector_watch.py.
"""

FEEDS = [
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com/rss"},
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml"},

    # Nordiska myndighets-CERT:s (officiella flöden). Island saknar ett
    # känt publikt RSS-flöde.
    {"name": "CERT-SE (Sverige)", "url": "https://www.cert.se/feed.rss"},
    {"name": "NSM NCSC (Norge)",
     "url": "https://nsm.no/fagomrader/digital-sikkerhet/nasjonalt-cybersikkerhetssenter/varsler-fra-ncsc/rss/"},
    {"name": "DKCERT (Danmark)", "url": "https://www.cert.dk/news/rss"},
    {"name": "NCSC-FI (Finland)", "url": "https://www.kyberturvallisuuskeskus.fi/feed/rss/en"},
]
