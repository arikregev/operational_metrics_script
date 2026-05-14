"""ecosyste.ms client.

Two services consulted:
  * ``packages.ecosyste.ms`` — package-level metadata (downloads, dependents,
    repo_metadata, status, funding). Bulk endpoint takes up to 100 purls/req.
  * ``advisories.ecosyste.ms`` — vulnerability advisories with EPSS scoring,
    looked up per-purl (no bulk).

Polite-tier requires both a contact ``mailto=`` query param and a ``User-Agent``
that includes the email; doing so gives 15k requests/hour vs 5k anonymous.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from enrich.types import SourceRecord

log = logging.getLogger(__name__)

PKG_BASE = "https://packages.ecosyste.ms"
ADV_BASE = "https://advisories.ecosyste.ms"
BULK_PATH = "/api/v1/packages/lookup"  # POST many; some deployments name it /lookup, fallback below
BULK_PATH_ALT = "/api/v1/packages/bulk_lookup"
SINGLE_PATH = "/api/v1/packages/lookup"
ADVISORY_PATH = "/api/v1/advisories/lookup"
BULK_CHUNK = 100
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


def _normalize_package(p: dict[str, Any]) -> dict[str, Any]:
    repo = p.get("repo_metadata") or {}
    return {
        "ecosystem": (p.get("ecosystem") or "").lower() or None,
        "name": p.get("name"),
        "latest_release_number": p.get("latest_release_number"),
        "latest_release_published_at": p.get("latest_release_published_at"),
        "first_release_published_at": p.get("first_release_published_at"),
        "versions_count": p.get("versions_count"),
        "licenses": p.get("licenses"),
        "normalized_licenses": p.get("normalized_licenses"),
        "downloads": p.get("downloads"),
        "downloads_period": p.get("downloads_period"),
        "dependent_packages_count": p.get("dependent_packages_count"),
        "dependent_repos_count": p.get("dependent_repos_count"),
        "status": p.get("status"),
        "funding_links": p.get("funding_links"),
        "repo_metadata": {
            "stargazers_count": repo.get("stargazers_count"),
            "forks_count": repo.get("forks_count"),
            "open_issues_count": repo.get("open_issues_count"),
            "total_commits": repo.get("total_commits"),
            "total_committers": repo.get("total_committers"),
            "pushed_at": repo.get("pushed_at"),
            "archived": repo.get("archived"),
        }
        if repo
        else None,
    }


def _aggregate_advisories(advisories: list[dict[str, Any]]) -> dict[str, Any]:
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cve_ids: list[str] = []
    max_cvss = None
    max_epss_percentile = None
    for a in advisories:
        sev = (a.get("severity") or "").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        cvss = a.get("cvss_score")
        if isinstance(cvss, (int, float)):
            max_cvss = cvss if max_cvss is None else max(max_cvss, cvss)
        epss = a.get("epss_percentile")
        if isinstance(epss, (int, float)):
            max_epss_percentile = (
                epss if max_epss_percentile is None else max(max_epss_percentile, epss)
            )
        for ident in a.get("identifiers") or []:
            if isinstance(ident, str) and ident.upper().startswith("CVE-"):
                cve_ids.append(ident)
    return {
        "count": len(advisories),
        "critical": sev_counts["critical"],
        "high": sev_counts["high"],
        "medium": sev_counts["medium"],
        "low": sev_counts["low"],
        "max_cvss": max_cvss,
        "max_epss_percentile": max_epss_percentile,
        "cve_ids": sorted(set(cve_ids)),
    }


async def _bulk_chunk(
    client: httpx.AsyncClient, purls: list[str], mailto: str
) -> dict[str, dict | None]:
    """POST one bulk request; tries the documented path then a known alias."""
    body = {"purls": purls}
    params = {"mailto": mailto}
    for path in (BULK_PATH_ALT, BULK_PATH):
        try:
            async for attempt in AsyncRetrying(**_retry):
                with attempt:
                    r = await client.post(path, json=body, params=params)
                    if r.status_code == 404:
                        raise httpx.HTTPStatusError(
                            "no bulk endpoint", request=r.request, response=r
                        )
                    r.raise_for_status()
                    data = r.json()
                    break
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (404, 405):
                continue
            raise
        return _index_bulk_response(data, purls)
    # Both bulk endpoints unavailable — caller falls back to single lookups.
    return {p: None for p in purls}


def _strip_version(purl: str) -> str:
    """Return the purl body without the trailing ``@version``."""
    if not purl.startswith("pkg:"):
        return purl
    body = purl[4:]
    at = body.rfind("@")
    return f"pkg:{body[:at]}" if at != -1 else f"pkg:{body}"


def _index_bulk_response(data: Any, requested: list[str]) -> dict[str, dict | None]:
    """Map response items back to the requested purls.

    ecosyste.ms's bulk_lookup ignores ``@version`` and returns the package
    record keyed by the unversioned purl. We reverse-map by stripping the
    version from each requested purl, so the response gets attributed to the
    original (versioned) input key.
    """
    items = data if isinstance(data, list) else (data.get("results") or data.get("packages") or [])
    reverse: dict[str, str] = {_strip_version(p): p for p in requested}
    by_purl: dict[str, dict | None] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        rpurl = item.get("purl")
        if not rpurl:
            continue
        if rpurl in requested:
            by_purl[rpurl] = _normalize_package(item)
            continue
        key = reverse.get(_strip_version(rpurl))
        if key:
            by_purl[key] = _normalize_package(item)
    for p in requested:
        by_purl.setdefault(p, None)
    return by_purl


async def _single_lookup(
    client: httpx.AsyncClient, purl: str, mailto: str
) -> dict | None:
    params = {"purl": purl, "mailto": mailto}
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.get(SINGLE_PATH, params=params)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()
            break
    if isinstance(data, list):
        data = data[0] if data else None
    if not data:
        return None
    return _normalize_package(data)


async def _advisory_lookup(
    client: httpx.AsyncClient, purl: str, mailto: str
) -> list[dict[str, Any]]:
    params = {"purl": purl, "mailto": mailto}
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.get(ADVISORY_PATH, params=params)
            if r.status_code == 404:
                return []
            r.raise_for_status()
            data = r.json()
            break
    if isinstance(data, dict):
        data = data.get("advisories") or data.get("results") or []
    return data or []


async def lookup_packages(
    pkg_client: httpx.AsyncClient,
    purls: list[str],
    sem: asyncio.Semaphore,
    mailto: str,
) -> dict[str, tuple[SourceRecord | None, str]]:
    """Bulk-look-up packages with single-lookup fallback for misses."""
    results: dict[str, tuple[SourceRecord | None, str]] = {}
    misses: list[str] = []
    chunks = [purls[i : i + BULK_CHUNK] for i in range(0, len(purls), BULK_CHUNK)]

    async def _do_chunk(chunk: list[str]) -> dict[str, dict | None]:
        async with sem:
            try:
                return await _bulk_chunk(pkg_client, chunk, mailto)
            except Exception as e:  # noqa: BLE001
                log.warning("ecosystems bulk failed (%d purls): %s", len(chunk), e)
                return {p: None for p in chunk}

    chunk_results = await asyncio.gather(*[_do_chunk(c) for c in chunks])
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
                    rec = await _single_lookup(pkg_client, p, mailto)
                    return p, rec, ("ok" if rec else "error:not_found")
                except Exception as e:  # noqa: BLE001
                    return p, None, f"error:{type(e).__name__}"

        fb = await asyncio.gather(*[_fallback(p) for p in misses])
        for p, rec, status in fb:
            results[p] = (rec, status)

    return results


async def attach_advisories(
    adv_client: httpx.AsyncClient,
    records: dict[str, tuple[SourceRecord | None, str]],
    sem: asyncio.Semaphore,
    mailto: str,
) -> dict[str, tuple[SourceRecord | None, str]]:
    """For every record, fetch advisories and attach aggregated counters under ``_agg``."""
    purls = list(records.keys())

    async def _do(purl: str) -> tuple[str, list[dict]]:
        async with sem:
            try:
                advs = await _advisory_lookup(adv_client, purl, mailto)
                return purl, advs
            except Exception as e:  # noqa: BLE001
                log.warning("ecosystems advisories %s failed: %s", purl, e)
                return purl, []

    pairs = await asyncio.gather(*[_do(p) for p in purls])
    for purl, advs in pairs:
        rec, status = records.get(purl, (None, "error:no_pkg_rec"))
        if rec is None:
            rec = {}
            status = status if status != "ok" else "ok"
        rec["_agg"] = _aggregate_advisories(advs)
        rec["advisories_raw_count"] = len(advs)
        # Promote record to ok when advisories alone are available.
        if status != "ok" and rec.get("_agg", {}).get("count", 0) > 0:
            status = "ok"
        records[purl] = (rec, status)
    return records


def make_pkg_client(mailto: str) -> httpx.AsyncClient:
    ua = f"operational-metrics-script ({mailto})"
    return httpx.AsyncClient(
        base_url=PKG_BASE,
        timeout=DEFAULT_TIMEOUT,
        headers={"Accept": "application/json", "User-Agent": ua},
        http2=True,
    )


def make_adv_client(mailto: str) -> httpx.AsyncClient:
    ua = f"operational-metrics-script ({mailto})"
    return httpx.AsyncClient(
        base_url=ADV_BASE,
        timeout=DEFAULT_TIMEOUT,
        headers={"Accept": "application/json", "User-Agent": ua},
        http2=True,
    )
