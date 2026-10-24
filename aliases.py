"""
Aktörsalias — slår ihop samma grupp som går under flera namn.

Källor:
  - MITRE ATT&CK (intrusion sets och malware, gratis, hämtas högst en gång per vecka)
  - en liten manuell lista nedan för ransomware-grupper som MITRE saknar eller kallar annorlunda

Användning:
  from aliases import canonical, aliases_of
  canonical("alphv")   -> "BlackCat"
  aliases_of("BlackCat") -> ["ALPHV", ...]

Om hämtningen från MITRE misslyckas används det som redan finns i databasen, och annars bara
den manuella listan. Ett alias som pekar på två olika grupper hoppas över (tvetydigt).
"""

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import requests

from storage import DB_PATH

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
TIMEOUT = 120
REFRESH_DAYS = 7
MIN_ALIAS_LEN = 4  # korta alias från MITRE ignoreras (risk för kollisioner med vanliga ord)

# alias (gemener) -> kanoniskt namn. Bara sådant som är allmänt känt.
MANUAL = {
    "alphv": "BlackCat", "blackcat": "BlackCat", "alphv blackcat": "BlackCat",
    "lockbit3": "LockBit", "lockbit 3.0": "LockBit", "lockbit3.0": "LockBit", "lockbit 5.0": "LockBit",
    "lockbit5": "LockBit", "lockbit": "LockBit", "lockbitsupp": "LockBit",
    "revil": "REvil", "sodinokibi": "REvil",
    "royal": "BlackSuit", "blacksuit": "BlackSuit",
    "playcrypt": "Play", "play": "Play",
    "clop": "Cl0p", "cl0p": "Cl0p",
    "blackbasta": "Black Basta", "black basta": "Black Basta",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS actor_aliases (
    alias TEXT PRIMARY KEY,
    canonical TEXT NOT NULL,
    source TEXT
);
CREATE TABLE IF NOT EXISTS alias_meta (key TEXT PRIMARY KEY, value TEXT);
"""

_cache = {}


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.executescript(_SCHEMA)
    return conn


def _load(db_path: str) -> dict:
    if db_path in _cache:
        return _cache[db_path]
    mapping = {}
    try:
        conn = _connect(db_path)
        mapping = {a: c for a, c in conn.execute("SELECT alias, canonical FROM actor_aliases")}
        conn.close()
    except sqlite3.Error:
        pass
    _cache[db_path] = mapping
    return mapping


def canonical(name: str, db_path: str = DB_PATH) -> str:
    """Returnerar kanoniskt gruppnamn, eller namnet oförändrat om inget alias finns."""
    n = (name or "").strip()
    low = n.lower()
    if low in MANUAL:
        return MANUAL[low]
    if len(low) >= MIN_ALIAS_LEN:
        hit = _load(db_path).get(low)
        if hit:
            return hit
    return n


def aliases_of(canon: str, db_path: str = DB_PATH) -> list:
    low = (canon or "").lower()
    out = {a for a, c in _load(db_path).items() if c.lower() == low and a != low}
    out |= {a for a, c in MANUAL.items() if c.lower() == low and a != low}
    return sorted(out)


def _due(conn) -> bool:
    row = conn.execute("SELECT value FROM alias_meta WHERE key = 'fetched'").fetchone()
    if not row:
        return True
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(row[0]) > timedelta(days=REFRESH_DAYS)
    except ValueError:
        return True


def parse_mitre(bundle: dict) -> tuple:
    """Returnerar ({alias_lower: kanoniskt}, antal tvetydiga). Gruppnamn vinner över malware-namn."""
    pairs, ambiguous = {}, set()

    def add(alias, canon):
        a = (alias or "").strip().lower()
        if len(a) < MIN_ALIAS_LEN or not canon:
            return
        if a in pairs and pairs[a] != canon:
            ambiguous.add(a)
        else:
            pairs[a] = canon

    for kind in ("intrusion-set", "malware"):
        for obj in bundle.get("objects", []):
            if obj.get("type") != kind or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            canon = obj.get("name", "").strip()
            names = obj.get("aliases") or obj.get("x_mitre_aliases") or []
            for n in [canon] + list(names):
                add(n, canon)
    for a in ambiguous:
        pairs.pop(a, None)
    return pairs, len(ambiguous)


def run_aliases(db_path: str = DB_PATH, force: bool = False) -> int:
    conn = _connect(db_path)
    if not force and not _due(conn):
        n = conn.execute("SELECT COUNT(*) FROM actor_aliases").fetchone()[0]
        conn.close()
        print("[+] Aktörsalias: redan uppdaterade denna vecka.")
        return n
    conn.close()

    print("[+] Aktörsalias: hämtar MITRE ATT&CK ...")
    resp = requests.get(MITRE_URL, timeout=TIMEOUT, headers={"User-Agent": "cti-agent"})
    resp.raise_for_status()
    pairs, amb = parse_mitre(json.loads(resp.content))
    if not pairs:
        raise RuntimeError("inga alias hittades i MITRE-data")
    conn = _connect(db_path)
    conn.execute("DELETE FROM actor_aliases")
    conn.executemany("INSERT OR REPLACE INTO actor_aliases (alias, canonical, source) VALUES (?, ?, 'mitre')", pairs.items())
    conn.execute("INSERT OR REPLACE INTO alias_meta (key, value) VALUES ('fetched', ?)", (datetime.now(timezone.utc).isoformat(),))
    conn.commit()
    conn.close()
    _cache.pop(db_path, None)
    print(f"    Aktörsalias: {len(pairs)} alias sparade ({amb} tvetydiga hoppades över).", file=sys.stdout)
    return len(pairs)


if __name__ == "__main__":
    run_aliases(force=True)
