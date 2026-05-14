"""Orchestrator: drives the four-source DAG, persists every result to the
SQLite cache as soon as it is computed, then emits merged rows."""
from __future__ import annotations

import asyncio
import logging
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from enrich.cache import Cache
from enrich.merge import COLUMNS, merge
from enrich.sources import depsdev, ecosystems, github, scorecard, snyk
from enrich.types import ALL_SOURCES, SourceName

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Settings:
    github_token: str
    snyk_token: str
    snyk_org_id: str
    contact_email: str
    concurrency: float = 1.0


def _scale(default: int, factor: float) -> int:
    return max(1, int(round(default * factor)))


async def run(
    purls: list[str],
    cache: Cache,
    settings: Settings,
) -> Iterable[dict]:
    """Fetch any missing data and yield merged rows in *purls*' original order."""
    fully = await cache.fully_cached()
    pending = [p for p in purls if p not in fully]
    log.info("%d total purls; %d cached, %d pending", len(purls), len(fully), len(pending))

    if pending:
        await _run_fetch_phase(pending, cache, settings)

    records_by_purl = await cache.load_all(purls)
    rows = []
    for purl in purls:
        per_source: dict[SourceName, tuple[dict | None, str]] = {}
        for src in ALL_SOURCES:
            per_source[src] = records_by_purl.get(purl, {}).get(src, (None, "missing"))
        rows.append(merge(purl, per_source))
    return rows


async def _run_fetch_phase(
    pending: list[str],
    cache: Cache,
    settings: Settings,
) -> None:
    """Concurrently run all four source layers, persisting as we go."""
    c = settings.concurrency
    sems = {
        "depsdev": asyncio.Semaphore(_scale(10, c)),
        "depsdev_proj": asyncio.Semaphore(_scale(8, c)),
        "ecosystems_pkg": asyncio.Semaphore(_scale(8, c)),
        "ecosystems_adv": asyncio.Semaphore(_scale(8, c)),
        "github": asyncio.Semaphore(_scale(5, c)),
        "scorecard": asyncio.Semaphore(_scale(5, c)),
        "snyk": asyncio.Semaphore(_scale(3, c)),
    }

    async with AsyncExitStack() as stack:
        dd_client = await stack.enter_async_context(depsdev.make_client())
        eco_pkg = await stack.enter_async_context(ecosystems.make_pkg_client(settings.contact_email))
        eco_adv = await stack.enter_async_context(ecosystems.make_adv_client(settings.contact_email))
        gh_client = await stack.enter_async_context(github.make_client(settings.github_token))
        sc_client = await stack.enter_async_context(scorecard.make_client())
        snyk_client = await stack.enter_async_context(snyk.make_client(settings.snyk_token))

        async def _do_depsdev() -> dict[str, tuple[dict | None, str]]:
            missing = await cache.missing_for_source(pending, "depsdev")
            log.info("deps.dev: fetching %d/%d purls", len(missing), len(pending))
            results: dict[str, tuple[dict | None, str]] = {}
            if missing:
                results = await depsdev.batch_lookup(dd_client, missing, sems["depsdev"])
                results = await depsdev.enrich_projects(dd_client, results, sems["depsdev_proj"])
                await cache.put_many(
                    [(p, "depsdev", rec, status) for p, (rec, status) in results.items()]
                )
            # Reload all from cache so downstream sees both freshly-fetched and previously-cached.
            cached = await cache.load_all(pending)
            return {p: cached.get(p, {}).get("depsdev", (None, "missing")) for p in pending}

        async def _do_ecosystems() -> None:
            missing = await cache.missing_for_source(pending, "ecosystems")
            log.info("ecosyste.ms: fetching %d/%d purls", len(missing), len(pending))
            if not missing:
                return
            results = await ecosystems.lookup_packages(
                eco_pkg, missing, sems["ecosystems_pkg"], settings.contact_email
            )
            # Ensure every missing purl has an entry, even if package lookup failed
            for p in missing:
                results.setdefault(p, (None, "error:no_package"))
            results = await ecosystems.attach_advisories(
                eco_adv, results, sems["ecosystems_adv"], settings.contact_email
            )
            await cache.put_many(
                [(p, "ecosystems", rec, status) for p, (rec, status) in results.items()]
            )

        async def _do_snyk() -> None:
            missing = await cache.missing_for_source(pending, "snyk")
            log.info("snyk: fetching %d/%d purls", len(missing), len(pending))
            if not missing:
                return
            results = await snyk.lookup_issues(
                snyk_client, settings.snyk_org_id, missing, sems["snyk"]
            )
            await cache.put_many(
                [(p, "snyk", rec, status) for p, (rec, status) in results.items()]
            )

        # Stage 1: deps.dev, ecosystems, snyk run in parallel.
        async with asyncio.TaskGroup() as tg:
            depsdev_task = tg.create_task(_do_depsdev())
            tg.create_task(_do_ecosystems())
            tg.create_task(_do_snyk())

        depsdev_results = depsdev_task.result()

        # Stage 2: GitHub + Scorecard need owner/repo from deps.dev.
        repo_by_purl: dict[str, str | None] = {}
        for p in pending:
            rec, status = depsdev_results.get(p, (None, "missing"))
            repo = rec.get("github_repo") if isinstance(rec, dict) and status == "ok" else None
            repo_by_purl[p] = repo

        unique_repos = sorted({r for r in repo_by_purl.values() if r})
        log.info(
            "github+scorecard: %d unique repos for %d purls",
            len(unique_repos),
            sum(1 for r in repo_by_purl.values() if r),
        )

        # GitHub
        gh_missing_purls = await cache.missing_for_source(pending, "github")
        repos_to_fetch_gh = sorted(
            {repo_by_purl[p] for p in gh_missing_purls if repo_by_purl.get(p)}
        )
        gh_repo_records = {}
        if repos_to_fetch_gh:
            gh_repo_records = await github.lookup_repos(
                gh_client, list(repos_to_fetch_gh), sems["github"]
            )

        gh_rows: list[tuple[str, SourceName, dict | None, str]] = []
        for p in gh_missing_purls:
            repo = repo_by_purl.get(p)
            if not repo:
                gh_rows.append((p, "github", None, "no_repo"))
                continue
            rec = gh_repo_records.get(repo)
            if rec is None:
                gh_rows.append((p, "github", None, "error:not_found"))
            else:
                gh_rows.append((p, "github", rec, "ok"))
        await cache.put_many(gh_rows)

        # Scorecard
        sc_missing_purls = await cache.missing_for_source(pending, "scorecard")
        repos_to_fetch_sc = sorted(
            {repo_by_purl[p] for p in sc_missing_purls if repo_by_purl.get(p)}
        )
        sc_repo_records: dict[str, tuple[dict | None, str]] = {}
        if repos_to_fetch_sc:
            sc_repo_records = await scorecard.lookup_repos(
                sc_client, list(repos_to_fetch_sc), sems["scorecard"]
            )

        sc_rows: list[tuple[str, SourceName, dict | None, str]] = []
        for p in sc_missing_purls:
            repo = repo_by_purl.get(p)
            if not repo:
                sc_rows.append((p, "scorecard", None, "no_repo"))
                continue
            rec_tuple = sc_repo_records.get(repo)
            if rec_tuple is None:
                sc_rows.append((p, "scorecard", None, "error:missing"))
            else:
                rec, status = rec_tuple
                sc_rows.append((p, "scorecard", rec, status))
        await cache.put_many(sc_rows)


def write_csv(rows: Iterable[dict], path: Path) -> int:
    from enrich.io import write_rows

    return write_rows(path, COLUMNS, rows)
