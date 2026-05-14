"""deps.dev (Google Open Source Insights) client.

Two phases:
  1. ``batch_lookup(purls)`` POSTs to ``/v3alpha/purlbatch`` in chunks; falls back
     to per-purl ``GET /v3alpha/purl/{quoted_purl}`` for misses.
  2. ``enrich_projects(records)`` fetches OpenSSF Scorecard data for any
     normalized record that resolved a ``github_repo``.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Iterable
from urllib.parse import quote

import httpx
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from enrich.types import SourceRecord

log = logging.getLogger(__name__)

BASE = "https://api.deps.dev"
BATCH_PATH = "/v3alpha/purlbatch"
SINGLE_PATH = "/v3alpha/purl/{}"
PROJECT_PATH = "/v3/projects/{}"
BATCH_CHUNK = 500
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code == 429 or code >= 500
    return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))


_retry = dict(
    retry=retry_if_exception(_is_retryable),
    wait=wait_exponential_jitter(initial=1, max=30),
    stop=stop_after_attempt(5),
    reraise=True,
)


def _has_version(purl: str) -> bool:
    # Naive but correct for canonical purls: a version follows the LAST '@'
    # that appears after the type prefix ('pkg:'). Scoped npm puts '%40' early.
    tail = purl.rsplit("@", 1)
    return len(tail) == 2 and tail[1] != ""


def _normalize_version(version: dict[str, Any] | None) -> dict[str, Any] | None:
    """Flatten a deps.dev Version object into our normalized shape."""
    if not version:
        return None
    vkey = version.get("versionKey") or {}
    advisories = [a.get("id") for a in version.get("advisoryKeys") or [] if a.get("id")]
    licenses = list(version.get("licenses") or [])
    github_repo = None
    for rel in version.get("relatedProjects") or []:
        pid = (rel.get("projectKey") or {}).get("id") or ""
        rtype = (rel.get("relationType") or rel.get("type") or "").upper()
        if pid.startswith("github.com/") and (
            "SOURCE" in rtype or rtype in ("REPO", "REPO_SOURCE", "HOSTED_REPO", "")
        ):
            github_repo = pid[len("github.com/") :]
            break
    return {
        "version_key": {
            "system": (vkey.get("system") or "").lower() or None,
            "name": vkey.get("name"),
            "version": vkey.get("version"),
        },
        "published_at": version.get("publishedAt"),
        "is_default": version.get("isDefault"),
        "is_deprecated": version.get("isDeprecated"),
        "deprecation_reason": version.get("deprecationReason"),
        "licenses": licenses,
        "advisory_keys": advisories,
        "github_repo": github_repo,
    }


async def _batch_chunk(client: httpx.AsyncClient, purls: list[str]) -> dict[str, dict | None]:
    """POST one chunk of purls; returns purl -> normalized record (None on error)."""
    body = {"requests": [{"purl": p} for p in purls]}
    out: dict[str, dict | None] = {}
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.post(BATCH_PATH, json=body)
            r.raise_for_status()
            data = r.json()
            break
    for resp in data.get("responses") or []:
        req_purl = (resp.get("request") or {}).get("purl") or ""
        if not req_purl:
            continue
        if resp.get("error"):
            out[req_purl] = None
            continue
        version = resp.get("version") or resp.get("result", {}).get("version")
        out[req_purl] = _normalize_version(version)
    # Anything not present in the response — mark None so caller can fall back.
    for p in purls:
        out.setdefault(p, None)
    return out


async def _single_lookup(client: httpx.AsyncClient, purl: str) -> dict | None:
    encoded = quote(purl, safe="")
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.get(SINGLE_PATH.format(encoded))
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()
            break
    version = data.get("version") if isinstance(data, dict) else None
    return _normalize_version(version)


async def batch_lookup(
    client: httpx.AsyncClient,
    purls: list[str],
    sem: asyncio.Semaphore,
) -> dict[str, tuple[SourceRecord | None, str]]:
    """Look up *purls* on deps.dev. Returns purl -> (record, status).

    status is 'ok', 'no_version' (purl missing @version), or 'error:<msg>'.
    """
    results: dict[str, tuple[SourceRecord | None, str]] = {}
    versioned: list[str] = []
    for p in purls:
        if not _has_version(p):
            results[p] = (None, "no_version")
        else:
            versioned.append(p)

    chunks = [versioned[i : i + BATCH_CHUNK] for i in range(0, len(versioned), BATCH_CHUNK)]
    misses: list[str] = []

    async def _do(chunk: list[str]) -> dict[str, dict | None]:
        async with sem:
            try:
                return await _batch_chunk(client, chunk)
            except Exception as e:  # noqa: BLE001
                log.warning("deps.dev batch failed (%d purls): %s", len(chunk), e)
                return {p: None for p in chunk}

    chunk_results = await asyncio.gather(*[_do(c) for c in chunks])
    for cr in chunk_results:
        for p, rec in cr.items():
            if rec is None:
                misses.append(p)
            else:
                results[p] = (rec, "ok")

    if misses:
        async def _fallback(p: str) -> tuple[str, dict | None, str]:
            async with sem:
                try:
                    rec = await _single_lookup(client, p)
                    return p, rec, ("ok" if rec else "error:not_found")
                except Exception as e:  # noqa: BLE001
                    return p, None, f"error:{type(e).__name__}"

        fb = await asyncio.gather(*[_fallback(p) for p in misses])
        for p, rec, status in fb:
            results[p] = (rec, status)

    return results


async def _project(client: httpx.AsyncClient, github_repo: str) -> dict | None:
    pid = f"github.com/{github_repo}"
    encoded = quote(pid, safe="")
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.get(PROJECT_PATH.format(encoded))
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()
            break
    scorecard = data.get("scorecard") or {}
    checks: dict[str, float] = {}
    for c in scorecard.get("checks") or []:
        name = c.get("name")
        score = c.get("score")
        if name is not None and score is not None:
            checks[name] = score
    return {
        "open_issues_count": data.get("openIssuesCount"),
        "stars_count": data.get("starsCount"),
        "forks_count": data.get("forksCount"),
        "license": data.get("license"),
        "description": data.get("description"),
        "scorecard": {
            "overall_score": scorecard.get("overallScore"),
            "checks": checks,
            "date": scorecard.get("date"),
        }
        if scorecard
        else None,
    }


async def enrich_projects(
    client: httpx.AsyncClient,
    records: dict[str, tuple[SourceRecord | None, str]],
    sem: asyncio.Semaphore,
) -> dict[str, tuple[SourceRecord | None, str]]:
    """Attach ``project`` data (incl. deps.dev scorecard) for any record with a github_repo."""
    repos: dict[str, list[str]] = {}
    for purl, (rec, status) in records.items():
        if status != "ok" or not rec:
            continue
        repo = rec.get("github_repo")
        if repo:
            repos.setdefault(repo, []).append(purl)

    if not repos:
        return records

    async def _do(repo: str) -> tuple[str, dict | None]:
        async with sem:
            try:
                return repo, await _project(client, repo)
            except Exception as e:  # noqa: BLE001
                log.warning("deps.dev project %s failed: %s", repo, e)
                return repo, None

    by_repo = dict(await asyncio.gather(*[_do(r) for r in repos]))
    for repo, project in by_repo.items():
        if not project:
            continue
        for purl in repos[repo]:
            rec, status = records[purl]
            if rec is None:
                continue
            rec["project"] = project
            records[purl] = (rec, status)
    return records


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=BASE,
        timeout=DEFAULT_TIMEOUT,
        headers={"Accept": "application/json", "User-Agent": "operational-metrics-script"},
        http2=True,
    )
