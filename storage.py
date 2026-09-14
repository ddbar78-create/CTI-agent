"""
Enkel SQLite-lagring för insamlade artiklar och extraherade IOCs.
Byt gärna ut mot Postgres/MISP/OpenCTI när projektet växer.
"""

import sqlite3
from contextlib import contextmanager

DB_PATH = "cti.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed TEXT NOT NULL,
    title TEXT NOT NULL,
    link TEXT UNIQUE NOT NULL,
    published TEXT,
    summary TEXT,
    fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY (article_id) REFERENCES articles(id),
    UNIQUE(article_id, ioc_type, value)
);

CREATE TABLE IF NOT EXISTS daily_counts (
    date TEXT PRIMARY KEY,
    new_articles INTEGER DEFAULT 0,
    new_iocs_regex INTEGER DEFAULT 0,
    new_iocs_threatfox INTEGER DEFAULT 0,
    new_telegram INTEGER DEFAULT 0,
    new_ransomware_victims INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ip_enrichment (
    ip TEXT PRIMARY KEY,
    ports TEXT,
    hostnames TEXT,
    vulns TEXT,
    tags TEXT,
    checked_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cve_enrichment (
    cve_id TEXT PRIMARY KEY,
    cvss REAL,
    epss REAL,
    kev INTEGER DEFAULT 0,
    ransomware_campaign TEXT,
    summary TEXT,
    checked_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


@contextmanager
def get_conn(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH):
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)
        _migrate_llm_columns(conn)
        _migrate_full_text_column(conn)


def _migrate_full_text_column(conn):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(articles)")
    existing = {row[1] for row in cur.fetchall()}
    if "full_text" not in existing:
        cur.execute("ALTER TABLE articles ADD COLUMN full_text TEXT")


def save_full_text(conn, article_id: int, text: str):
    cur = conn.cursor()
    cur.execute("UPDATE articles SET full_text = ? WHERE id = ?", (text, article_id))


def _migrate_llm_columns(conn):
    """Lägger till LLM-kontextkolumner på articles om de saknas (säkert att
    köra flera gånger — hoppar bara över kolumner som redan finns)."""
    new_columns = {
        "llm_actor": "TEXT",
        "llm_ttps": "TEXT",
        "llm_sector": "TEXT",
        "llm_severity": "TEXT",
        "llm_summary": "TEXT",
    }
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(articles)")
    existing = {row[1] for row in cur.fetchall()}
    for col, col_type in new_columns.items():
        if col not in existing:
            cur.execute(f"ALTER TABLE articles ADD COLUMN {col} {col_type}")


def save_llm_enrichment(conn, article_id: int, enrichment: dict):
    """Sparar LLM-extraherad kontext för en artikel."""
    ttps = enrichment.get("ttps") or []
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE articles
        SET llm_actor = ?, llm_ttps = ?, llm_sector = ?,
            llm_severity = ?, llm_summary = ?
        WHERE id = ?
        """,
        (
            enrichment.get("threat_actor"),
            ", ".join(ttps) if isinstance(ttps, list) else str(ttps),
            enrichment.get("target_sector"),
            enrichment.get("severity"),
            enrichment.get("one_line_summary"),
            article_id,
        ),
    )


def record_daily_stats(conn, **kwargs):
    """
    Ökar dagens räknare i daily_counts med de värden som anges, t.ex.:
    record_daily_stats(conn, new_articles=5, new_iocs_threatfox=3540)
    Skapar dagens rad om den inte redan finns. Säkert att anropa flera
    gånger samma dag (adderar, skriver inte över).
    """
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO daily_counts (date) VALUES (?) ON CONFLICT(date) DO NOTHING",
        (today,),
    )
    valid_columns = {
        "new_articles", "new_iocs_regex", "new_iocs_threatfox",
        "new_telegram", "new_ransomware_victims",
    }
    for key, value in kwargs.items():
        if key in valid_columns and value:
            cur.execute(
                f"UPDATE daily_counts SET {key} = {key} + ? WHERE date = ?",
                (value, today),
            )


def get_daily_stats(db_path: str = DB_PATH, days: int = 30) -> list:
    """Hämtar de senaste N dagarnas summeringar, i kronologisk ordning."""
    with get_conn(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM daily_counts ORDER BY date DESC LIMIT ?", (days,)
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    return list(reversed(rows))


def get_unenriched_ips(db_path: str = DB_PATH, limit: int = 20) -> list:
    """
    Hittar IP-adresser från iocs-tabellen (typ ipv4 eller ip:port) som
    ännu inte har slagits upp mot Shodan InternetDB.
    """
    with get_conn(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT DISTINCT value FROM iocs
            WHERE ioc_type IN ('ipv4', 'ip:port')
            """
        )
        raw_values = [row[0] for row in cur.fetchall()]

        # ip:port-värden från ThreatFox har formatet "1.2.3.4:443  [malware, ...]"
        # — plocka ut bara själva IP-delen.
        ips = set()
        for v in raw_values:
            ip_part = v.split(":")[0].split(" ")[0].strip()
            if ip_part:
                ips.add(ip_part)

        cur.execute("SELECT ip FROM ip_enrichment")
        already_checked = {row[0] for row in cur.fetchall()}

    return list(ips - already_checked)[:limit]


def save_ip_enrichment(conn, ip: str, ports: list, hostnames: list, vulns: list, tags: list):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO ip_enrichment (ip, ports, hostnames, vulns, tags)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            ports = excluded.ports, hostnames = excluded.hostnames,
            vulns = excluded.vulns, tags = excluded.tags,
            checked_at = CURRENT_TIMESTAMP
        """,
        (
            ip,
            ", ".join(str(p) for p in ports),
            ", ".join(hostnames),
            ", ".join(vulns),
            ", ".join(tags),
        ),
    )


def get_unenriched_cves(db_path: str = DB_PATH, limit: int = 30) -> list:
    """Hittar CVE-ID:n från iocs-tabellen som ännu inte har slagits upp mot CVEDB."""
    with get_conn(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT value FROM iocs WHERE ioc_type = 'cve'")
        all_cves = {row[0].upper() for row in cur.fetchall()}

        cur.execute("SELECT cve_id FROM cve_enrichment")
        already_checked = {row[0] for row in cur.fetchall()}

    return list(all_cves - already_checked)[:limit]


def save_cve_enrichment(conn, cve_id: str, cvss, epss, kev: bool,
                         ransomware_campaign, summary: str):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cve_enrichment (cve_id, cvss, epss, kev, ransomware_campaign, summary)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            cvss = excluded.cvss, epss = excluded.epss, kev = excluded.kev,
            ransomware_campaign = excluded.ransomware_campaign,
            summary = excluded.summary, checked_at = CURRENT_TIMESTAMP
        """,
        (cve_id, cvss, epss, int(bool(kev)), ransomware_campaign, summary),
    )


def save_article(conn, feed: str, title: str, link: str, published: str, summary: str):
    """Sparar en artikel. Returnerar article_id, eller None om den redan finns."""
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO articles (feed, title, link, published, summary) "
            "VALUES (?, ?, ?, ?, ?)",
            (feed, title, link, published, summary),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None  # redan sparad (link är UNIQUE)


def save_iocs(conn, article_id: int, iocs: dict):
    cur = conn.cursor()
    for ioc_type, values in iocs.items():
        for value in values:
            cur.execute(
                "INSERT OR IGNORE INTO iocs (article_id, ioc_type, value) "
                "VALUES (?, ?, ?)",
                (article_id, ioc_type, value),
            )


def recent_iocs(db_path: str = DB_PATH, limit: int = 50):
    with get_conn(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT iocs.ioc_type, iocs.value, articles.title, articles.link
            FROM iocs
            JOIN articles ON articles.id = iocs.article_id
            ORDER BY articles.id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()
