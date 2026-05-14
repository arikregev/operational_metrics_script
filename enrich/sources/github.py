"""GitHub client: one batched GraphQL query + per-repo /community/profile REST.

The GraphQL query uses aliases (``r0``, ``r1``, …) to fetch up to 25 repos in a
single request. Each request also pulls ``rateLimit { cost remaining resetAt }``
so we can pause when the budget drops.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
from typing import Any

import httpx
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from enrich.types import SourceRecord

log = logging.getLogger(__name__)

API_BASE = "https://api.github.com"
GRAPHQL_PATH = "/graphql"
COMMUNITY_PATH = "/repos/{owner}/{repo}/community/profile"
GRAPHQL_BATCH = 25
DEFAULT_TIMEOUT = httpx.Timeout(45.0, connect=10.0)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code == 429 or code in (502, 503, 504) or code >= 500
    return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))


_retry = dict(
    retry=retry_if_exception(_is_retryable),
    wait=wait_exponential_jitter(initial=2, max=60),
    stop=stop_after_attempt(5),
    reraise=True,
)


_REPO_FRAGMENT = """\
stargazerCount
forkCount
watchers { totalCount }
isArchived
isDisabled
pushedAt
defaultBranchRef { target { ... on Commit { committedDate } } }
issues(states: OPEN) { totalCount }
pullRequests(states: OPEN) { totalCount }
releases { totalCount }
latestRelease { publishedAt }
licenseInfo { spdxId }
primaryLanguage { name }
repositoryTopics(first: 15) { nodes { topic { name } } }
"""


def _build_query(repos: list[tuple[str, str]]) -> str:
    parts = ["query {", "  rateLimit { cost remaining resetAt }"]
    for i, (owner, name) in enumerate(repos):
        # Escape quotes defensively (GH owners/names cannot legally contain them).
        o = owner.replace('"', '\\"')
        n = name.replace('"', '\\"')
        parts.append(f'  r{i}: repository(owner: "{o}", name: "{n}") {{')
        parts.append(_REPO_FRAGMENT)
        parts.append("  }")
    parts.append("}")
    return "\n".join(parts)


def _normalize_repo(node: dict[str, Any] | None) -> dict[str, Any] | None:
    if not node:
        return None
    default_branch = (node.get("defaultBranchRef") or {}).get("target") or {}
    topics = [
        (t.get("topic") or {}).get("name")
        for t in ((node.get("repositoryTopics") or {}).get("nodes") or [])
        if t
    ]
    topics = [t for t in topics if t]
    return {
        "stars": node.get("stargazerCount"),
        "forks": node.get("forkCount"),
        "watchers": (node.get("watchers") or {}).get("totalCount"),
        "is_archived": node.get("isArchived"),
        "is_disabled": node.get("isDisabled"),
        "pushed_at": node.get("pushedAt"),
        "default_branch_last_commit_at": default_branch.get("committedDate"),
        "open_issues": (node.get("issues") or {}).get("totalCount"),
        "open_prs": (node.get("pullRequests") or {}).get("totalCount"),
        "releases_count": (node.get("releases") or {}).get("totalCount"),
        "latest_release_at": (node.get("latestRelease") or {}).get("publishedAt"),
        "license_spdx": (node.get("licenseInfo") or {}).get("spdxId"),
        "primary_language": (node.get("primaryLanguage") or {}).get("name"),
        "topics": topics,
    }


async def _maybe_sleep_for_rate(rate: dict[str, Any] | None) -> None:
    if not rate:
        return
    remaining = rate.get("remaining")
    reset_at = rate.get("resetAt")
    if remaining is None or remaining > 100 or not reset_at:
        return
    try:
        reset_dt = dt.datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return
    delta = (reset_dt - dt.datetime.now(dt.timezone.utc)).total_seconds()
    if delta > 0:
        log.warning("GitHub GraphQL near rate limit (remaining=%s); sleeping %.0fs", remaining, delta)
        await asyncio.sleep(min(delta + 1, 900))


async def _graphql_batch(
    client: httpx.AsyncClient, repos: list[tuple[str, str]]
) -> tuple[dict[tuple[str, str], dict | None], dict[str, Any] | None]:
    query = _build_query(repos)
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.post(GRAPHQL_PATH, json={"query": query})
            r.raise_for_status()
            data = r.json()
            break
    out: dict[tuple[str, str], dict | None] = {}
    payload = data.get("data") or {}
    for i, (owner, name) in enumerate(repos):
        node = payload.get(f"r{i}")
        out[(owner, name)] = _normalize_repo(node) if node else None
    rate = payload.get("rateLimit")
    if data.get("errors"):
        log.debug("GitHub GraphQL errors: %s", data["errors"])
    return out, rate


async def _community(client: httpx.AsyncClient, owner: str, name: str) -> dict | None:
    async for attempt in AsyncRetrying(**_retry):
        with attempt:
            r = await client.get(COMMUNITY_PATH.format(owner=owner, repo=name))
            if r.status_code in (404, 451):
                return None
            r.raise_for_status()
            data = r.json()
            break
    files = data.get("files") or {}
    return {
        "health_percentage": data.get("health_percentage"),
        "has_code_of_conduct": bool(files.get("code_of_conduct")),
        "has_contributing": bool(files.get("contributing")),
        "has_readme": bool(files.get("readme")),
        "has_license": bool(files.get("license")),
        "has_issue_template": bool(files.get("issue_template")),
        "has_pull_request_template": bool(files.get("pull_request_template")),
    }


async def lookup_repos(
    client: httpx.AsyncClient,
    repos: list[str],
    sem: asyncio.Semaphore,
) -> dict[str, SourceRecord]:
    """Run GraphQL + community calls for unique ``owner/repo`` strings."""
    if not repos:
        return {}
    unique = sorted(set(repos))
    pairs: list[tuple[str, str]] = []
    for r in unique:
        if "/" not in r:
            continue
        owner, name = r.split("/", 1)
        if owner and name:
            pairs.append((owner, name))

    results: dict[str, SourceRecord] = {}
    chunks = [pairs[i : i + GRAPHQL_BATCH] for i in range(0, len(pairs), GRAPHQL_BATCH)]

    async def _do_graphql(chunk: list[tuple[str, str]]) -> None:
        async with sem:
            try:
                graphs, rate = await _graphql_batch(client, chunk)
                for (owner, name), node in graphs.items():
                    key = f"{owner}/{name}"
                    results.setdefault(key, {})
                    if node:
                        results[key].update(node)
                await _maybe_sleep_for_rate(rate)
            except Exception as e:  # noqa: BLE001
                log.warning("GitHub graphql batch failed: %s", e)

    await asyncio.gather(*[_do_graphql(c) for c in chunks])

    async def _do_community(owner: str, name: str) -> None:
        async with sem:
            try:
                comm = await _community(client, owner, name)
                key = f"{owner}/{name}"
                results.setdefault(key, {})
                if comm:
                    results[key]["community"] = comm
            except Exception as e:  # noqa: BLE001
                log.warning("GitHub community %s/%s failed: %s", owner, name, e)

    await asyncio.gather(*[_do_community(o, n) for (o, n) in pairs])
    return results


def make_client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=API_BASE,
        timeout=DEFAULT_TIMEOUT,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "operational-metrics-script",
        },
        http2=True,
        trust_env=True,  # honor HTTPS_PROXY / HTTP_PROXY / NO_PROXY
    )
