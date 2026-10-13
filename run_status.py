
"""
Källstatus — håller reda på vilka källor som fungerade i senaste körningen.

Varje källa (ThreatFox, ransomware.live, varje RSS-flöde, KEV, ...) skriver
en rad: lyckades den, hur många nya poster, och ev. felmeddelande. Dashboarden
visar raderna som en statusrad, så man direkt ser om något slutat fungera
(t.ex. en RSS-adress som ändrats) utan att öppna Actions-loggen.

ok = 1 (lyckades), 0 (misslyckades), -1 (ej konfigurerad, t.ex. saknar API-nyckel)

OBS: record() öppnar en egen databasanslutning. Anropa den därför aldrig
medan en annan 'with get_conn()'-transaktion med skrivningar är öppen.
"""

import sqlite3
import sys

from storage import DB_PATH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_status (
    source TEXT PRIMARY KEY,
    ok INTEGER,
    count INTEGER DEFAULT 0,
    error TEXT DEFAULT '',
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
)
"""


def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute(_SCHEMA)
    return conn


def record(source: str, ok: int, count: int = 0, error: str = "", db_path: str = DB_PATH):
    """Skriver/uppdaterar statusraden för en källa. Får aldrig fälla agenten."""
    try:
        conn = _connect(db_path)
        conn.execute(
            """
            INSERT INTO run_status (source, ok, count, error, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(source) DO UPDATE SET
                ok = excluded.ok, count = excluded.count,
                error = excluded.error, updated_at = CURRENT_TIMESTAMP
            """,
            (source, int(ok), int(count or 0), str(error or "")[:200]),
        )
        conn.commit()
        conn.close()
    except Exception as e:  # pragma: no cover
        print(f"    (kunde inte spara källstatus för {source}: {e})", file=sys.stderr)


def get_all(db_path: str = DB_PATH) -> list:
    try:
        conn = _connect(db_path)
        cur = conn.execute(
            "SELECT source, ok, count, error, updated_at FROM run_status ORDER BY ok ASC, source ASC"
        )
        rows = [dict(zip(["source", "ok", "count", "error", "updated_at"], r)) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def _count_of(result) -> int:
    if isinstance(result, bool):
        return int(result)
    if isinstance(result, int):
        return result
    try:
        return len(result)
    except TypeError:
        return 0


def tracked(source: str, fn, *args, default=0, **kwargs):
    """
    Kör fn(*args, **kwargs) och registrerar utfallet. Vid fel loggas det,
    statusen sätts till misslyckad och 'default' returneras — så att en
    enskild källa aldrig stoppar hela agenten.
    """
    try:
        result = fn(*args, **kwargs)
    except Exception as e:
        print(f"    {source}: FEL – {e}", file=sys.stderr)
        record(source, 0, 0, str(e))
        return default
    record(source, 1, _count_of(result))
    return result
