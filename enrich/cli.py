"""Command-line entry point. Reads .env, validates config, runs the pipeline."""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from enrich.cache import Cache
from enrich.io import read_purls
from enrich.pipeline import Settings, run, write_csv


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="enrich",
        description=(
            "Enrich a CSV of purl_canonical values with operational-metrics data from "
            "deps.dev, ecosyste.ms, GitHub, and Snyk."
        ),
    )
    p.add_argument("input", type=Path, help="Input CSV with a 'purl_canonical' column.")
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output CSV path (overwrites if it exists).",
    )
    p.add_argument(
        "--refresh",
        action="store_true",
        help="Wipe the local cache before running; re-fetch every purl from every source.",
    )
    p.add_argument(
        "--concurrency",
        type=float,
        default=1.0,
        help="Multiplier applied to default per-source semaphores (default: 1.0).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process only the first N unique purls (useful for smoke tests).",
    )
    p.add_argument(
        "--cache-path",
        type=Path,
        default=Path(".cache/enrich.sqlite"),
        help="Path to the SQLite cache file (default: ./.cache/enrich.sqlite).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v for INFO, -vv for DEBUG.",
    )
    return p.parse_args(argv)


def _setup_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy libs unless -vv.
    if verbose < 2:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


def _build_settings(concurrency: float) -> Settings:
    missing = [k for k in ("GITHUB_TOKEN", "SNYK_TOKEN", "SNYK_ORG_ID") if not os.environ.get(k)]
    if missing:
        sys.stderr.write(
            f"Missing required environment variables: {', '.join(missing)}.\n"
            "Set them in your shell or a .env file in the current directory.\n"
        )
        sys.exit(2)
    return Settings(
        github_token=os.environ["GITHUB_TOKEN"].strip(),
        snyk_token=os.environ["SNYK_TOKEN"].strip(),
        snyk_org_id=os.environ["SNYK_ORG_ID"].strip(),
        contact_email=(
            os.environ.get("CONTACT_EMAIL", "").strip() or "operational-metrics-script@local"
        ),
        snyk_api_base=(os.environ.get("SNYK_API_BASE", "").strip() or "https://api.snyk.io"),
        snyk_api_version=(os.environ.get("SNYK_API_VERSION", "").strip() or "2024-10-15"),
        concurrency=max(0.1, concurrency),
    )


async def _amain(args: argparse.Namespace) -> int:
    settings = _build_settings(args.concurrency)
    purls = read_purls(args.input)
    if args.limit:
        purls = purls[: args.limit]
    if not purls:
        sys.stderr.write(f"No purls found in {args.input}.\n")
        return 1
    print(f"Loaded {len(purls)} unique purls from {args.input}")

    cache = await Cache.open(args.cache_path)
    try:
        if args.refresh:
            print("--refresh: wiping cache")
            await cache.truncate()
        rows = await run(purls, cache, settings)
    finally:
        await cache.close()

    rows = list(rows)
    written = write_csv(rows, args.output)
    print(f"Wrote {written} rows to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    load_dotenv()  # picks up .env in CWD
    args = _parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return asyncio.run(_amain(args))
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
