"""
Håller cti.db hanterbar i storlek över tid.

Utan detta växer databasen obegränsat — ThreatFox ensam kan lägga till
tusentals rader per körning. Git (och GitHub) hanterar inte obegränsat
växande binärfiler bra, så vi rensar bort gamla råa poster efter en viss
tid. De AGGREGERADE dagliga summeringarna (daily_counts) rensas ALDRIG,
så trendgrafen i dashboarden fortsätter fungera för hela historiken även
efter att detaljerna rensats bort.

Olika källor får olika livslängd eftersom volymen skiljer sig enormt:
ThreatFox producerar tusentals rader/timme och behöver kort livslängd,
medan RSS/Telegram/ransomware.live är lågvolym och kan sparas länge.
"""

from storage import get_conn

RETENTION_DAYS = {
    "ThreatFox (abuse.ch)": 7,   # extremt hög volym — korta liv för enskilda IOCs
    "default": 90,                # RSS / Telegram / ransomware.live — låg volym, spara länge
}


def prune_old_data():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT feed FROM articles")
        feeds = [row[0] for row in cur.fetchall()]

        total_deleted = 0
        for feed in feeds:
            days = RETENTION_DAYS.get(feed, RETENTION_DAYS["default"])

            cur.execute(
                """
                DELETE FROM iocs WHERE article_id IN (
                    SELECT id FROM articles
                    WHERE feed = ? AND fetched_at < datetime('now', ?)
                )
                """,
                (feed, f"-{days} days"),
            )
            cur.execute(
                "DELETE FROM articles WHERE feed = ? AND fetched_at < datetime('now', ?)",
                (feed, f"-{days} days"),
            )
            total_deleted += cur.rowcount

        conn.commit()  # avsluta transaktionen innan VACUUM (krävs av SQLite)

        if total_deleted:
            print(f"    Rensade {total_deleted} gamla poster (retention-policy)")
            cur.execute("VACUUM")
        else:
            print("    Inget att rensa än.")


if __name__ == "__main__":
    prune_old_data()
