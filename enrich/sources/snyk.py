"""Snyk client (REST API ``/orgs/{org}/ecosystems/{ecosystem}/{package_name}``).

The base URL and API version are configurable via ``SNYK_API_BASE`` and
``SNYK_API_VERSION`` env vars to support custom Snyk deployments.

Aggregates issue listings into per-purl counters: severity counts, max CVSS,
exploit maturity flag, fix availability flag, license-issue count, CVE list.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import quote, unquote

import httpx
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from enrich.types import SourceRecord

log = logging.getLogger(__name__)

DEFAULT_BASE = "https://api.snyk.io"
DEFAULT_API_VERSION = "2024-10-15"
PACKAGE_PATH = "/orgs/{org}/ecosystems/{ecosystem}/{package_name}"
DEFAULT_TIMEOUT = httpx.Timeout(45.0, connect=10.0)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code == 429 or code >= 500
    return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))


_retry = dict(
    retry=retry_if_exception(_is_retryable),
    wait=wait_exponential_jitter(initial=2, max=60),
    stop=stop_after_attempt(6),
    reraise=True,
)


def _split_purl(purl: str) -> tuple[str, str, str | None]:
    """Return ``(ecosystem, package_name, version)`` parsed from *purl*.

    ``package_name`` is URL-decoded so scoped npm names come back as
    ``@scope/name`` rather than ``%40scope/name``. Returns ``(ecosystem, "", None)``
    if the purl shape is malformed.
    """
    if not purl.startswith("pkg:"):
        return "", "", None
    body = purl[4:]
    body = body.split("?", 1)[0].split("#", 1)[0]
    type_sep = body.find("/")
    if type_sep == -1:
        return "", "", None
    ecosystem = body[:type_sep].lower()
    rest = body[type_sep + 1 :]
    at = rest.rfind("@")
    if at == -1:
        return ecosystem, unquote(rest), None
    return ecosystem, unquote(rest[:at]), rest[at + 1 :]


def _max_cvss(issue: dict[str, Any]) -> float | None:
    best = None
    for s in issue.get("attributes", {}).get("severities") or []:
        score = s.get("score")
        if isinstance(score, (int, float)):
            best = score if best is None else max(best, score)
    return best


def _cves_from_problems(issue: dict[str, Any]) -> list[str]:
    out = []
    for p in issue.get("attributes", {}).get("problems") or []:
        pid = (p.get("id") or "").upper()
        if pid.startswith("CVE-"):
            out.append(pid)
    return out


def _has_remedy(issue: dict[str, Any]) -> bool:
    for c in issue.get("attributes", {}).get("coordinates") or []:
        if c.get("remedies"):
            return True
    return False


_MATURE = {"mature", "proof of concept", "proof-of-concept"}


def _is_exploit_mature(issue: dict[str, Any]) -> bool:
    details = issue.get("attributes", {}).get("exploit_details") or {}
    maturity = (details.get("maturity_levels") or details.get("maturity") or "")
    if isinstance(maturity, list):
        return any((m or "").lower() in _MATURE for m in maturity)
    return (maturity or "").lower() in _MATURE


def _aggregate(issues: list[dict[str, Any]]) -> dict[str, Any]:
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cves: list[str] = []
    max_cvss = None
    exploit_mature = False
    has_fix = False
    license_issues = 0
    for issue in issues:
        attrs = issue.get("attributes") or {}
        kind = (attrs.get("type") or "").lower()
        if kind == "license":
            license_issues += 1
        lvl = (attrs.get("effective_severity_level") or "").lower()
        if lvl in sev:
            sev[lvl] += 1
        score = _max_cvss(issue)
        if score is not None:
            max_cvss = score if max_cvss is None else max(max_cvss, score)
        if _is_exploit_mature(issue):
            exploit_mature = True
        if _has_remedy(issue):
            has_fix = True
        cves.extend(_cves_from_problems(issue))
    return {
        "total": len(issues),
        "critical": sev["critical"],
        "high": sev["high"],
        "medium": sev["medium"],
        "low": sev["low"],
        "max_cvss": max_cvss,
        "exploit_mature": exploit_mature,
        "has_fix": has_fix,
        "license_issues": license_issues,
        "cve_ids": sorted(set(cves)),
    }


async def _fetch_all_issues(
    client: httpx.AsyncClient,
    org_id: str,
    ecosystem: str,
    package_name: str,
    api_version: str,
    base_url: str,
) -> list[dict[str, Any]]:
    # Keep '/' inside the package name (maven groupId/artifactId, golang import paths);
    # encode everything else (scoped npm '@scope/name' -> '%40scope/name').
    encoded_eco = quote(ecosystem, safe="")
    encoded_name = quote(package_name, safe="/")
    path = PACKAGE_PATH.format(org=org_id, ecosystem=encoded_eco, package_name=encoded_name)
    params: dict[str, Any] = {"version": api_version, "limit": 100}
    issues: list[dict[str, Any]] = []
    next_url: str | None = None
    while True:
        async for attempt in AsyncRetrying(**_retry):
            with attempt:
                if next_url:
                    r = await client.get(next_url)
                else:
                    r = await client.get(path, params=params)
                if r.status_code == 404:
                    return issues
                if r.status_code == 429:
                    retry_after = float(r.headers.get("Retry-After", "5"))
                    log.info("Snyk 429 — sleeping %.0fs", retry_after)
                    await asyncio.sleep(retry_after)
                r.raise_for_status()
                data = r.json()
                break
        items = data.get("data") or []
        issues.extend(items)
        links = data.get("links") or {}
        nxt = links.get("next")
        if not nxt:
            break
        next_url = nxt if nxt.startswith("http") else f"{base_url}{nxt}"
    return issues


async def lookup_issues(
    client: httpx.AsyncClient,
    org_id: str,
    purls: list[str],
    sem: asyncio.Semaphore,
    api_version: str = DEFAULT_API_VERSION,
    base_url: str = DEFAULT_BASE,
) -> dict[str, tuple[SourceRecord | None, str]]:
    out: dict[str, tuple[SourceRecord | None, str]] = {}

    async def _do(purl: str) -> None:
        ecosystem, package_name, _version = _split_purl(purl)
        if not ecosystem or not package_name:
            out[purl] = (None, "error:invalid_purl")
            return
        async with sem:
            try:
                issues = await _fetch_all_issues(
                    client, org_id, ecosystem, package_name, api_version, base_url
                )
                agg = _aggregate(issues)
                out[purl] = ({"_agg": agg, "issue_count": len(issues)}, "ok")
            except Exception as e:  # noqa: BLE001
                log.warning("snyk %s failed: %s", purl, e)
                out[purl] = (None, f"error:{type(e).__name__}")

    await asyncio.gather(*[_do(p) for p in purls])
    return out


def make_client(token: str, base_url: str = DEFAULT_BASE) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=base_url,
        timeout=DEFAULT_TIMEOUT,
        headers={
            "Authorization": f"token {token}",  # lowercase 'token', NOT Bearer
            "Accept": "application/vnd.api+json",
            "User-Agent": "operational-metrics-script",
        },
        http2=True,
    )
