"""Type aliases and source-name constants shared across modules."""
from __future__ import annotations

from typing import Any, Literal

SourceName = Literal["depsdev", "ecosystems", "github", "scorecard", "snyk"]

ALL_SOURCES: tuple[SourceName, ...] = (
    "depsdev",
    "ecosystems",
    "github",
    "scorecard",
    "snyk",
)

SourceRecord = dict[str, Any]
CacheStatus = Literal["ok", "no_repo", "no_version"] | str
