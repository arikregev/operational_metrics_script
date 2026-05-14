"""Resumable SQLite cache for normalized per-source records.

One row per (purl, source). Payloads are JSON of the normalized record dict.
A purl is "fully cached" when there is a row for every source in
``types.ALL_SOURCES`` — even no-repo and error states count, so we never retry
a permanent failure on resume. Use ``truncate()`` (via the CLI ``--refresh``
flag) to start over.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite

from enrich.types import ALL_SOURCES, SourceName, SourceRecord


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    purl TEXT NOT NULL,
    source TEXT NOT NULL,
    payload TEXT,
    status TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (purl, source)
);
CREATE INDEX IF NOT EXISTS idx_cache_purl ON cache (purl);
"""


class Cache:
    def __init__(self, db: aiosqlite.Connection):
        self._db = db

    @classmethod
    async def open(cls, path: Path) -> "Cache":
        path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(path)
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA synchronous=NORMAL;")
        await db.executescript(_SCHEMA)
        await db.commit()
        return cls(db)

    async def close(self) -> None:
        await self._db.close()

    async def truncate(self) -> None:
        await self._db.execute("DELETE FROM cache;")
        await self._db.commit()

    async def get(
        self, purl: str, source: SourceName
    ) -> tuple[SourceRecord | None, str] | None:
        """Return ``(payload, status)`` for *(purl, source)*, or ``None`` if missing."""
        async with self._db.execute(
            "SELECT payload, status FROM cache WHERE purl = ? AND source = ?",
            (purl, source),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        payload_json, status = row
        payload = json.loads(payload_json) if payload_json else None
        return payload, status

    async def put(
        self,
        purl: str,
        source: SourceName,
        payload: SourceRecord | None,
        status: str,
    ) -> None:
        await self._db.execute(
            """
            INSERT INTO cache (purl, source, payload, status, fetched_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(purl, source) DO UPDATE SET
                payload = excluded.payload,
                status = excluded.status,
                fetched_at = excluded.fetched_at
            """,
            (
                purl,
                source,
                json.dumps(payload, default=str) if payload is not None else None,
                status,
            ),
        )
        await self._db.commit()

    async def put_many(self, rows: list[tuple[str, SourceName, SourceRecord | None, str]]) -> None:
        if not rows:
            return
        await self._db.executemany(
            """
            INSERT INTO cache (purl, source, payload, status, fetched_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(purl, source) DO UPDATE SET
                payload = excluded.payload,
                status = excluded.status,
                fetched_at = excluded.fetched_at
            """,
            [
                (
                    p,
                    s,
                    json.dumps(pl, default=str) if pl is not None else None,
                    st,
                )
                for (p, s, pl, st) in rows
            ],
        )
        await self._db.commit()

    async def fully_cached(self) -> set[str]:
        """Return the set of purls that have a row for every source in ``ALL_SOURCES``."""
        n = len(ALL_SOURCES)
        async with self._db.execute(
            """
            SELECT purl FROM cache
            WHERE source IN ({})
            GROUP BY purl
            HAVING COUNT(DISTINCT source) = ?
            """.format(",".join("?" * n)),
            (*ALL_SOURCES, n),
        ) as cur:
            return {row[0] for row in await cur.fetchall()}

    async def missing_for_source(self, purls: list[str], source: SourceName) -> list[str]:
        """Return the subset of *purls* with no cache row for *source*."""
        if not purls:
            return []
        # Chunk to stay under SQLite's variable limit.
        out: list[str] = []
        chunk = 500
        for i in range(0, len(purls), chunk):
            batch = purls[i : i + chunk]
            placeholders = ",".join("?" * len(batch))
            async with self._db.execute(
                f"SELECT purl FROM cache WHERE source = ? AND purl IN ({placeholders})",
                (source, *batch),
            ) as cur:
                have = {row[0] for row in await cur.fetchall()}
            out.extend(p for p in batch if p not in have)
        return out

    async def load_all(
        self, purls: list[str]
    ) -> dict[str, dict[SourceName, tuple[SourceRecord | None, str]]]:
        """Bulk-fetch every cached source record for the given purls."""
        out: dict[str, dict[SourceName, tuple[SourceRecord | None, str]]] = {p: {} for p in purls}
        if not purls:
            return out
        chunk = 500
        for i in range(0, len(purls), chunk):
            batch = purls[i : i + chunk]
            placeholders = ",".join("?" * len(batch))
            async with self._db.execute(
                f"SELECT purl, source, payload, status FROM cache WHERE purl IN ({placeholders})",
                tuple(batch),
            ) as cur:
                async for purl, source, payload_json, status in cur:
                    payload = json.loads(payload_json) if payload_json else None
                    out[purl][source] = (payload, status)
        return out


async def open_cache(path: Path) -> Cache:
    return await Cache.open(path)
