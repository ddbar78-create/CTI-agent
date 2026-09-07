"""
Lista över OSINT/CTI-källor (RSS-flöden).
Lägg till egna feeds här — t.ex. leverantörsbloggar, CERT-flöden,
eller din branschs ISAC om de erbjuder RSS.
"""

FEEDS = [
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com/rss"},
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml"},
]
