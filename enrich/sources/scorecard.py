"""OpenSSF Scorecard client (api.securityscorecards.dev, anonymous).

404 just means the project hasn't been scored — common for long-tail repos.
We record a ``no_repo``/``error:not_found`` status and write None payload.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from enrich.types import SourceRecord

log = logging.getLogger(__name__)

BASE = "https://api.securityscorecards.dev"
PROJECT_PATH = "/projects/github.com/{owner}/{repo}"
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code == 429 or exc.response.status_code >= 500
    return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))


_retry = dict(
    retry=retry_if_exception(_is_retryable),
    wait=wait_exponential_jitter(initial=2, max=30),
    stop=stop_after_attempt(4),
    reraise=True,
)


def _normalize(data: dict[str, Any]) -> dict[str, Any]:
    checks: dict[str, float] = {}
    for c in data.get("checks") or []:
        name = c.get("name")
        score = c.get("score")
        if name and score is not None:
            checks[name] = score
    return {
        "score": data.get("score"),
        "date": data.get("date"),
        "checks": checks,
    }


async def _fetch_one(client: httpx.AsyncClient, owner: str, name: str) -> dict | None:
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.get(PROJECT_PATH.format(owner=owner, repo=name))
            if r.status_code in (404, 451):
                return None
            r.raise_for_status()
            data = r.json()
            break
    return _normalize(data)


async def lookup_repos(
    client: httpx.AsyncClient,
    repos: list[str],
    sem: asyncio.Semaphore,
) -> dict[str, tuple[SourceRecord | None, str]]:
    """Returns owner/repo -> (record, status). Status is 'ok' or 'error:not_found' on 404."""
    out: dict[str, tuple[SourceRecord | None, str]] = {}

    async def _do(repo: str) -> None:
        if "/" not in repo:
            out[repo] = (None, "error:invalid_repo")
            return
        owner, name = repo.split("/", 1)
        async with sem:
            try:
                rec = await _fetch_one(client, owner, name)
                out[repo] = (rec, "ok") if rec else (None, "error:not_found")
            except Exception as e:  # noqa: BLE001
                log.warning("scorecard %s failed: %s", repo, e)
                out[repo] = (None, f"error:{type(e).__name__}")

    await asyncio.gather(*[_do(r) for r in sorted(set(repos))])
    return out


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=BASE,
        timeout=DEFAULT_TIMEOUT,
        headers={"Accept": "application/json", "User-Agent": "operational-metrics-script"},
        http2=True,
    )
