"""CSV input/output helpers."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable


def read_purls(path: Path) -> list[str]:
    """Read distinct ``purl_canonical`` values from *path*, preserving input order.

    Other columns are ignored. Blank/whitespace cells and duplicates are dropped.
    Raises ``ValueError`` if the header lacks ``purl_canonical``.
    """
    seen: set[str] = set()
    purls: list[str] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "purl_canonical" not in reader.fieldnames:
            raise ValueError(
                f"{path}: expected a 'purl_canonical' column in the header; "
                f"got {reader.fieldnames!r}"
            )
        for row in reader:
            purl = (row.get("purl_canonical") or "").strip()
            if not purl or purl in seen:
                continue
            seen.add(purl)
            purls.append(purl)
    return purls


def write_rows(path: Path, columns: list[str], rows: Iterable[dict]) -> int:
    """Write *rows* to *path* with header *columns*. Returns the number of rows written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: _stringify(row.get(c)) for c in columns})
            count += 1
    return count


def _stringify(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(v) for v in value)
    return value
