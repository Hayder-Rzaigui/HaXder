import sqlite3
import logging
from contextlib import contextmanager
from typing import Set, Dict

log = logging.getLogger("haxder")

SCHEMA = """
    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        base_domain TEXT,
        subdomain TEXT UNIQUE,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""


class Database:
    """Lightweight SQLite-backed store used for historical diffing and dashboard stats."""

    def __init__(self, db_path: str = "haxder.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        try:
            with self._connect() as conn:
                conn.execute(SCHEMA)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_base_domain ON subdomains(base_domain)")
                conn.commit()
        except Exception as exc:
            log.error("Database initialization error: %s", exc)

    def get_previous_subdomains(self, base_domain: str) -> Set[str]:
        """Returns a set of previously discovered subdomains for the given base domain."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT subdomain FROM subdomains WHERE base_domain = ?", (base_domain,)
                ).fetchall()
                return {row[0] for row in rows}
        except Exception as exc:
            log.error("Error reading from database: %s", exc)
            return set()

    def get_all_subdomains(self) -> Dict[str, list]:
        """Returns all domains and subdomains grouped by base domain for the Graph."""
        grouped: Dict[str, list] = {}
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT base_domain, subdomain FROM subdomains").fetchall()
                for base, sub in rows:
                    grouped.setdefault(base, []).append(sub)
        except Exception as exc:
            log.error("Error reading from database: %s", exc)
        return grouped

    def get_stats(self) -> Dict[str, int]:
        """Returns statistics for the dashboard."""
        try:
            with self._connect() as conn:
                base_count, sub_count = conn.execute(
                    "SELECT COUNT(DISTINCT base_domain), COUNT(subdomain) FROM subdomains"
                ).fetchone()
                return {"base_domains": base_count or 0, "subdomains": sub_count or 0}
        except Exception:
            return {"base_domains": 0, "subdomains": 0}

    def save_subdomains(self, base_domain: str, subdomains: Set[str]):
        """Saves a set of subdomains to the database, ignoring existing ones."""
        if not subdomains:
            return

        try:
            with self._connect() as conn:
                rows = [(base_domain, sub) for sub in subdomains]
                conn.executemany(
                    "INSERT OR IGNORE INTO subdomains (base_domain, subdomain) VALUES (?, ?)",
                    rows,
                )
                conn.commit()
        except Exception as exc:
            log.error("Error writing to database: %s", exc)
