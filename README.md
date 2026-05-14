# enrich — operational-metrics enrichment for `purl_canonical`

Read a CSV with a `purl_canonical` column, query **deps.dev**, **ecosyste.ms**,
**GitHub**, and **Snyk** in parallel, merge their fields by priority, and write
a single CSV with `purl_canonical` first and **63 operational-metrics columns**
covering identity, activity, popularity, license, deprecation, vulnerabilities
(EPSS + Snyk severities), OpenSSF Scorecard, and live GitHub repo health.

Built for runs of 5000+ purls: async I/O, batch endpoints where supported, a
resumable SQLite cache so an interrupted run picks up where it stopped, and
per-source partial-failure handling so one slow API can't block the rest.

---

## Why these four sources

| Source | Best at | Auth |
|---|---|---|
| [**deps.dev**](https://deps.dev) (Google) | Authoritative `isDeprecated`, links package → source repo (`relatedProjects`), OpenSSF Scorecard snapshot. Batch lookup up to 5000 purls/request. | anonymous |
| [**ecosyste.ms**](https://ecosyste.ms) | Downloads, dependent counts, **EPSS exploitability percentile**, normalized SPDX licenses, funding links, ranked repo metadata. | anonymous (polite tier with `mailto=`) |
| **GitHub** | Live repo health: stars, forks, archived/disabled, days since last commit, release cadence, community health %. | Bearer PAT |
| **Snyk** | Curated vulnerability DB: severity counts, max CVSS, exploit maturity, fixed-version availability — all addressable directly by purl. | token PAT + org UUID |

One source alone is incomplete. The script aggregates evidence across all four
and emits a wide, decision-ready row per package.

---

## Quick start

```bash
git clone https://github.com/<you>/operational_metrics_script.git
cd operational_metrics_script

python3.11 -m venv .venv && source .venv/bin/activate
pip install -e .

cp .env.example .env       # then edit .env with real tokens

enrich tests/smoke.csv -o /tmp/out.csv --limit 8 -v
```

Second run uses the cache and completes in milliseconds:

```bash
enrich tests/smoke.csv -o /tmp/out.csv --limit 8
```

---

## Configuration

All credentials come from environment variables (`python-dotenv` auto-loads
`.env` from CWD on startup):

| Variable | Required | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | yes | Bearer for GitHub REST + GraphQL. Classic PAT with `public_repo` is enough for public-repo signals; fine-grained PATs work too. |
| `SNYK_TOKEN` | yes | Snyk personal or service-account token. Used as `Authorization: token <value>` (lowercase `token`, **not** Bearer). |
| `SNYK_ORG_ID` | yes | Snyk org UUID. Find it under https://app.snyk.io/org/&lt;slug&gt;/manage/settings. Scopes the request to your org's entitlements. |
| `SNYK_API_BASE` | no | Override the Snyk API base URL — useful for private / custom Snyk deployments. Defaults to `https://api.snyk.io`. |
| `SNYK_API_VERSION` | no | Snyk REST API date version sent as the `version` query param. Defaults to `2024-10-15`. |
| `CONTACT_EMAIL` | no | Contact email for the ecosyste.ms polite-tier (`mailto=` query param + UA). Lifts the anonymous limit from 5k/hr to 15k/hr. Defaults to `operational-metrics-script@local`. |

`pyproject.toml` requires **Python 3.11+** (used for `asyncio.TaskGroup`).

### Proxies

All outbound HTTP clients honor standard proxy environment variables:

```bash
export HTTPS_PROXY=http://user:pass@proxy.example.com:8080   # primary — all APIs are HTTPS
export HTTP_PROXY=http://proxy.example.com:8080              # fallback
export NO_PROXY=api.snyk.io,internal.corp                    # CSV bypass list
```

`HTTPS_PROXY` / `https_proxy` / `HTTP_PROXY` / `http_proxy` / `ALL_PROXY` /
`NO_PROXY` are all recognized (httpx picks them up via `trust_env=True`).
The script logs which proxy is in use at startup with credentials redacted.

---

## CLI

```
enrich INPUT.csv -o OUTPUT.csv
       [--refresh]
       [--concurrency MULT]
       [--limit N]
       [--cache-path PATH]
       [-v | -vv]
```

| Flag | Meaning |
|---|---|
| `INPUT.csv` | Positional. Must contain a `purl_canonical` column. All other columns are ignored. |
| `-o, --output` | Output CSV. Overwritten if exists. |
| `--refresh` | Truncate the cache before running; re-fetch every purl from every source. |
| `--concurrency` | Multiplier applied to the default per-source semaphores. `2.0` is faster but more likely to hit rate limits. Default `1.0`. |
| `--limit N` | Process only the first N unique purls — handy for a smoke test. |
| `--cache-path` | Override the SQLite path. Default `./.cache/enrich.sqlite`. |
| `-v` / `-vv` | INFO / DEBUG logging (`httpx` stays at WARN unless `-vv`). |

Equivalent forms:

```bash
enrich input.csv -o out.csv          # via the installed entry point
python -m enrich input.csv -o out.csv  # via the module
```

---

## Supported ecosystems

The script doesn't restrict input by ecosystem — any valid purl flows through.
Per-source coverage varies, though:

| purl type | deps.dev | ecosyste.ms | GitHub / Scorecard | Snyk |
|---|:---:|:---:|:---:|:---:|
| `npm`, `pypi`, `maven`, `nuget`, `cargo`, `golang` | ✓ | ✓ | ✓ (if `relatedProjects` resolves) | ✓ |
| `composer`, `gem`, `pub`, `hex` | ✓ | ✓ | ✓ (if `relatedProjects` resolves) | ✓ |
| `rpm` (RHEL, Fedora, CentOS) | — | ✓ | — | ✓ |
| `deb` (Debian, Ubuntu) | — | ✓ | — | ✓ |
| `apk` (Alpine Linux) | — | ✓ | — | ✓ |
| `cocoapods`, `swift`, `conan` | — | partial | — | ✓ |

For OS packages (rpm/deb/apk), Snyk + ecosyste.ms supply vulnerability and
metadata; deps.dev doesn't track distro packages so `version_published_at`,
`relatedProjects` (and the github_*/scorecard_* columns) are usually empty.
The row is still emitted with `_errors=depsdev:error:not_found`.

`pkg:alpine/...` (non-standard) is normalized to `apk` at the Snyk layer so
both spellings work for vulnerability lookup.

---

## Output columns (63)

The full ordered list is defined in [`enrich/merge.py`](enrich/merge.py)
(`COLUMNS`). Grouped here for reference:

**Identity (3)** — `purl_canonical` (input), `ecosystem`, `package_name`.

**Release / activity (6)** — `latest_version`, `latest_release_published_at`,
`version_published_at`, `versions_count`, `is_default_version`,
`last_repo_pushed_at`.

**Popularity / usage (6)** — `downloads`, `downloads_period`,
`dependent_packages_count`, `dependent_repos_count`, `stars`, `forks`.

**License & funding (2)** — `licenses_spdx` (`;`-joined SPDX), `funding_links`.

**Deprecation (3)** — `is_deprecated`, `deprecation_reason`, `package_status`.

**Ecosyste.ms advisories (6)** — `eco_advisories_count`,
`eco_advisories_critical_count`, `eco_advisories_high_count`, `eco_max_cvss`,
**`eco_max_epss_percentile`** (only source for EPSS), `eco_cve_ids`.

**Snyk vulnerabilities (10)** — `snyk_issues_total`, severity counts
(`critical/high/medium/low`), `snyk_max_cvss`, `snyk_exploit_mature` (bool),
`snyk_has_fix` (bool), `snyk_license_issues`, `snyk_cve_ids`.

**OpenSSF Scorecard (13)** — overall + per-check scores 0–10: `Maintained`,
`Code-Review`, `Dangerous-Workflow`, `Branch-Protection`,
`Pinned-Dependencies`, `Vulnerabilities`, `License`, `Signed-Releases`, `SAST`,
`Security-Policy`, `Token-Permissions`, `Contributors`. The standalone OpenSSF
API outranks deps.dev's snapshotted scorecard.

**GitHub repo (13)** — `github_repo` (`owner/name` resolved from deps.dev),
`github_watchers`, `github_open_issues`, `github_open_prs`,
`github_releases_count`, `github_default_branch_last_commit_at`,
`github_is_archived`, `github_is_disabled`, `github_primary_language`,
`github_topics`, `github_health_percentage` (community profile),
`github_total_commits`, `github_total_committers`.

**Meta (1)** — `_errors`: comma-joined source names that errored on this purl.
Empty when clean.

---

## Architecture

### Execution DAG

```
        deps.dev  (batch up to 500/req) ─┬─► github + scorecard
                                         │   (needs owner/repo from deps.dev)
ecosyste.ms (bulk 100/req + advisories) ─┤
                                         │
Snyk        (per-purl, 180/min)─────────────► merge → CSV
```

`asyncio.TaskGroup` fans out deps.dev / ecosyste.ms / Snyk concurrently. GitHub
and Scorecard wait on deps.dev because the repo address comes from
deps.dev's `relatedProjects[]`. Merge happens after every source finishes (or
errors), reading normalized records back from the cache.

### File layout

```
enrich/
├── __init__.py
├── __main__.py            # `python -m enrich` shim
├── cli.py                 # argparse, .env loading, env-var validation, asyncio entry
├── pipeline.py            # 4-stage orchestrator, semaphores, cache writes
├── io.py                  # CSV read (purl_canonical only) + CSV write
├── cache.py               # aiosqlite, fully_cached(), missing_for_source(), load_all()
├── types.py               # SourceName Literal, ALL_SOURCES tuple
├── merge.py               # SIGNAL_MAP, COLUMNS, merge(purl, records)
└── sources/
    ├── depsdev.py         # /v3alpha/purlbatch + /v3/projects/{repo}
    ├── ecosystems.py      # /packages/lookup (bulk-aware) + /advisories/lookup
    ├── github.py          # /graphql (aliased, 25 repos/query) + /community/profile
    ├── scorecard.py       # api.securityscorecards.dev (anonymous)
    └── snyk.py            # /rest/orgs/{org}/packages/{purl}/issues
```

### Merge priority

Per-column "first non-null wins" priority is encoded in `SIGNAL_MAP` (see
[`enrich/merge.py`](enrich/merge.py)). The global order is:

> **ecosyste.ms → deps.dev → github → snyk**

Two notable exceptions:

- **OpenSSF Scorecard fields**: standalone `scorecard` API wins over
  deps.dev's snapshotted scorecard (fresher, same provider).
- **Vulnerability counters** (`eco_*` vs `snyk_*`): kept under separate columns
  rather than merged. Snyk and ecosyste.ms cover overlapping but not identical
  advisory sets; aggregating them would lose nuance.

---

## Caching & resume

State lives in `./.cache/enrich.sqlite` (created on first run):

```sql
CREATE TABLE cache (
    purl       TEXT NOT NULL,
    source     TEXT NOT NULL,
    payload    TEXT,                 -- normalized record JSON
    status     TEXT NOT NULL,        -- 'ok' | 'no_repo' | 'no_version' | 'error:<msg>'
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (purl, source)
);
```

- **Resume rule**: A purl is skipped on subsequent runs when all five source
  rows exist (`depsdev`, `ecosystems`, `github`, `scorecard`, `snyk`).
  no-repo and error statuses count — so permanent failures don't get retried.
- **`--refresh`** truncates the table and re-fetches everything.
- **WAL mode** is enabled so the cache is crash-safe across interrupted runs.

---

## Rate limits & scale

| Source | Default semaphore | Rate budget | Strategy |
|---|---|---|---|
| deps.dev | 10 (+8 project) | unpublished, generous | batch (500/req) first, single fallback |
| ecosyste.ms | 8 + 8 | 15k/hr polite-tier | bulk (100/req) first, single fallback |
| GitHub GraphQL | 5 (dynamic) | 5000 points/hr | aliased query (~1pt for 25 repos), sleep when `rateLimit.remaining < 100` |
| OpenSSF Scorecard | 5 | unmetered | 404 = no scorecard (common) |
| Snyk | 3 | 180 req/min | honors `Retry-After` on 429 |

`tenacity` wraps every HTTP call with exponential-jitter backoff (max 5 tries)
on 5xx / 429 / transport errors. 4xx other than 408/429 are permanent.

Multiply with `--concurrency 2.0` if you have headroom; back off to `0.5` if
you're hitting limits.

---

## Gotchas baked into the code

- **deps.dev purl encoding** — whole purl is one URL-path segment.
  `urllib.parse.quote(purl, safe="")` handles double-encoding of `@` inside
  scoped npm names.
- **ecosyste.ms `bulk_lookup` ignores `@version`** — responses come back keyed
  by the unversioned purl. The indexer reverse-maps each response back to the
  originally requested versioned key.
- **Ecosystem casing** — deps.dev uses `NPM`, ecosyste.ms uses `npm`.
  Both are normalized to lowercase on output.
- **Versionless input purls** — deps.dev `purlbatch` rejects them. Such rows
  fall back to ecosyste.ms only and record `status="no_version"` for deps.dev.
- **Snyk auth header** — literal string `token <PAT>`, lowercase `token`,
  **not** `Bearer`.
- **Snyk purl split** — the new endpoint takes `{ecosystem}/{package_name}` as
  separate path segments, not a single URL-encoded purl. `package_name` keeps
  `/` (maven `groupId/artifactId`, golang import paths) but URL-encodes other
  special chars (scoped npm `@scope/name` → `%40scope/name`). Version from the
  purl is currently dropped — Snyk's package-level endpoint returns issues
  across all versions of the package.
- **GitHub GraphQL aliasing** — 25 repos per query, one rate-limit point,
  query includes `rateLimit { cost remaining resetAt }` for self-throttling.

---

## Development

Smoke-test fixture (already in [`tests/smoke.csv`](tests/smoke.csv)) covers
the interesting purl shapes:

```csv
pkg:npm/express@4.18.2                                 # popular npm
pkg:npm/%40angular/core@17.0.0                         # scoped npm (encoded @)
pkg:pypi/requests@2.31.0                               # popular pypi
pkg:pypi/django@4.2.0                                  # security history
pkg:maven/org.apache.commons/commons-lang3@3.12.0      # maven groupId/artifactId
pkg:cargo/serde@1.0.193                                # cargo
pkg:golang/github.com/gin-gonic/gin@v1.9.1             # golang
pkg:npm/left-pad@1.3.0                                 # low-activity, sparse data
```

Sanity-check the schema and merge logic without hitting the network:

```bash
python - <<'PY'
from enrich.merge import COLUMNS, SIGNAL_MAP, merge
print(f"COLUMNS={len(COLUMNS)}, SIGNAL_MAP entries={len(SIGNAL_MAP)}")
assert all(c in COLUMNS for c in SIGNAL_MAP)
PY
```

To exercise the live deps.dev + ecosyste.ms calls (no tokens needed):

```bash
python - <<'PY'
import asyncio
from enrich.sources import depsdev, ecosystems

async def main():
    purls = ["pkg:npm/express@4.18.2"]
    sem = asyncio.Semaphore(5)
    async with depsdev.make_client() as c:
        print(await depsdev.batch_lookup(c, purls, sem))
asyncio.run(main())
PY
```

Adding a column:

1. Decide which source(s) carry the signal and pick the priority order.
2. Add an entry to `SIGNAL_MAP` in [`enrich/merge.py`](enrich/merge.py).
3. Add the column name to `COLUMNS` in the right group.
4. Make sure the source module's normalized record exposes the dotted path.
5. Run the smoke check above to verify the column count matches.

---

## Project history

The design choices, alternatives considered, and verification recipe are
captured in [`PLAN.md`](PLAN.md), written before implementation.

---

## License

[MIT](LICENSE) © 2026 Arik Regev
