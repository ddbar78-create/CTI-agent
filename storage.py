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
