"""Ukládání normalizovaných událostí do SQLite.

SQLite je záměrně zvoleno pro nasazení na jedné VPS: nulová správa,
odolné vůči pádu (WAL) a snadno přenositelné/zálohovatelné. Pro větší
flotilu senzorů lze data z jednotlivých VPS agregovat (viz docs/architecture.md).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from honeypot_collector.models import AttackEvent, event_columns

SCHEMA_VERSION = 1

_EVENT_COLUMNS = event_columns()

_CREATE_SQL = f"""
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key   TEXT NOT NULL UNIQUE,
    {", ".join(f"{c} TEXT" for c in _EVENT_COLUMNS)}
);

CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON attack_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_time     ON attack_events(event_time);
CREATE INDEX IF NOT EXISTS idx_events_category ON attack_events(category);
CREATE INDEX IF NOT EXISTS idx_events_country  ON attack_events(country);

CREATE TABLE IF NOT EXISTS ingest_state (
    path   TEXT PRIMARY KEY,
    inode  INTEGER NOT NULL,
    offset INTEGER NOT NULL
);
"""


class Storage:
    """Tenká vrstva nad SQLite pro události útoků a stav ingestu."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def init_db(self) -> None:
        with self._conn:
            self._conn.executescript(_CREATE_SQL)
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- zápis -----------------------------------------------------------
    def insert_event(self, event: AttackEvent) -> bool:
        """Vloží událost. Vrací True pokud byla nová (jinak byla deduplikována)."""
        return self.insert_events([event]) == 1

    def insert_events(self, events: Iterable[AttackEvent]) -> int:
        """Vloží dávku událostí. Vrací počet skutečně nově vložených řádků."""
        cols = ("dedup_key", *_EVENT_COLUMNS)
        placeholders = ", ".join("?" for _ in cols)
        sql = (
            f"INSERT OR IGNORE INTO attack_events ({', '.join(cols)}) "
            f"VALUES ({placeholders})"
        )
        inserted = 0
        with self._conn:
            for event in events:
                row = [event.dedup_key()]
                row.extend(_coerce(getattr(event, c)) for c in _EVENT_COLUMNS)
                cur = self._conn.execute(sql, row)
                inserted += cur.rowcount
        return inserted

    # -- stav ingestu ----------------------------------------------------
    def get_ingest_offset(self, path: str, inode: int) -> int:
        cur = self._conn.execute(
            "SELECT inode, offset FROM ingest_state WHERE path = ?", (path,)
        )
        row = cur.fetchone()
        if row is None or row["inode"] != inode:
            return 0
        return int(row["offset"])

    def set_ingest_offset(self, path: str, inode: int, offset: int) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO ingest_state(path, inode, offset) VALUES(?, ?, ?) "
                "ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset",
                (path, inode, offset),
            )

    # -- dotazy ----------------------------------------------------------
    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM attack_events").fetchone()[0])

    def top(self, column: str, limit: int = 10) -> list[tuple[str, int]]:
        if column not in _EVENT_COLUMNS:
            raise ValueError(f"Neznámý sloupec: {column}")
        cur = self._conn.execute(
            f"SELECT {column} AS value, COUNT(*) AS n FROM attack_events "
            f"WHERE {column} IS NOT NULL AND {column} != '' "
            f"GROUP BY {column} ORDER BY n DESC LIMIT ?",
            (limit,),
        )
        return [(row["value"], int(row["n"])) for row in cur.fetchall()]

    def stats(self) -> dict:
        total = self.count()
        distinct_ips = int(
            self._conn.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM attack_events WHERE src_ip IS NOT NULL"
            ).fetchone()[0]
        )
        return {
            "total_events": total,
            "distinct_src_ips": distinct_ips,
            "by_sensor": dict(self.top("sensor", 100)),
            "by_category": dict(self.top("category", 100)),
            "by_protocol": dict(self.top("protocol", 100)),
        }

    @contextmanager
    def iter_events(self) -> Iterator[Iterator[sqlite3.Row]]:
        cur = self._conn.execute(
            f"SELECT {', '.join(_EVENT_COLUMNS)} FROM attack_events ORDER BY id"
        )
        try:
            yield cur
        finally:
            cur.close()


def _coerce(value: object) -> object:
    """SQLite drží vše jako TEXT kvůli jednotnosti; None zůstává NULL."""
    if value is None:
        return None
    return str(value)
