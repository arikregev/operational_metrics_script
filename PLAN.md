# Plan: Operational-Metrics Enrichment Script

## Context

You need a Python script that takes a CSV (any columns; only `purl_canonical` is read), enriches each package URL with operational-metrics data from four external APIs, and writes a single CSV with `purl_canonical` as the first column plus aggregated signals.

**Why these signals matter:** "Operational metrics decisions" means evidence-based answers to questions like _is this package still maintained? how popular is it? is it deprecated? does it have known critical CVEs? does the upstream repo follow security hygiene (OpenSSF Scorecard)? is there an exploit in the wild?_ One source alone is incomplete — each of the four covers a different slice:

| Source | Best at |
|---|---|
| **deps.dev** (Google) | Authoritative `isDeprecated`, links package → source repo, OpenSSF Scorecard scores. Batch lookups up to 5k/req. |
| **ecosyste.ms** | Downloads, dependent counts, EPSS exploitability percentile, normalized licenses, funding links — richest package-level signals. |
| **GitHub** | Live repo health: archived/disabled, last commit, releases cadence, community health %. |
| **Snyk** | Curated vulnerability database with severity counts, exploit maturity, fix availability per purl. |

**Confirmed decisions (from clarifying questions):**
- Call order: deps.dev → ecosyste.ms → GitHub → Snyk
- Merge fill priority (first non-null wins): **ecosyste.ms > deps.dev > github > snyk**
- Credentials via env vars (`GITHUB_TOKEN`, `SNYK_TOKEN`, `SNYK_ORG_ID`); `.env` auto-loaded
- Scale: 5000+ purls per run → async, batched, SQLite-cached, resumable
- Missing GitHub repo → blank github_* fields, row still emitted

## Architecture

### File layout (`enrich/` package)

```
operational_metrics_script/
├── enrich/
│   ├── __init__.py          # version, exports
│   ├── cli.py               # argparse, env loading, asyncio entry, tqdm progress
│   ├── pipeline.py          # orchestrator: 4-stage DAG
│   ├── io.py                # CSV read (purl_canonical only) + CSV write
│   ├── cache.py             # aiosqlite wrapper (.cache/enrich.sqlite)
│   ├── types.py             # dataclasses: DepsDevRecord, EcosystemsRecord, GithubRecord, SnykRecord
│   ├── merge.py             # SIGNAL_MAP + COLUMNS + merge()
│   └── sources/
│       ├── depsdev.py       # /v3alpha/purlbatch + /v3/projects/{repo}
│       ├── ecosystems.py    # /packages/bulk_lookup + /advisories/lookup
│       ├── github.py        # GraphQL (aliased, 25 repos/query) + /community/profile
│       ├── scorecard.py     # api.securityscorecards.dev
│       └── snyk.py          # /rest/orgs/{org}/packages/{purl}/issues
├── pyproject.toml           # Python ≥3.11, deps below
├── .env.example             # template for tokens
└── README.md                # usage + token setup
```

### Dependencies (Python 3.11.9 confirmed installed)

`httpx[http2]`, `tenacity`, `python-dotenv`, `aiosqlite`, `tqdm`. No pandas, no pydantic — `csv` module + dataclasses are enough.

### Execution DAG

```
        deps.dev (batch ≤500/req) ──┬──► github+scorecard (needs repo) ─┐
                                    │                                    │
ecosyste.ms (bulk ≤100/req) ────────┤                                    ├──► merge → CSV
                                    │                                    │
Snyk (per-purl, 180/min) ───────────┴────────────────────────────────────┘
```

deps.dev, ecosyste.ms, Snyk run concurrently via `asyncio.TaskGroup`. GitHub waits on deps.dev (needs `relatedProjects[]` for `owner/repo`).

### Rate-limit budgets

| Source | Auth | Concurrency | Strategy |
|---|---|---|---|
| deps.dev | none | sem(10) | batch first, single fallback for misses |
| ecosyste.ms | mailto + UA | sem(8) | 15k/hr polite tier; bulk first |
| GitHub | Bearer PAT | sem(5), dynamic | watch `rateLimit.remaining`, sleep until `resetAt` if <100 |
| Scorecard | none | sem(5) | anonymous, 404s are normal |
| Snyk | `token <PAT>` | sem(3) | 180/min; honor `Retry-After` |

`tenacity` retries 5xx/429/timeout with `wait_exponential_jitter(initial=1, max=30)`, stops after 5 attempts. 4xx (except 408/429) is permanent.

### Cache (resume-safe)

SQLite at `./.cache/enrich.sqlite`:
```sql
CREATE TABLE cache(
  purl TEXT, source TEXT,
  payload TEXT,           -- JSON of normalized record
  status TEXT,            -- 'ok' | 'no_repo' | 'error:<msg>'
  fetched_at TIMESTAMP,
  PRIMARY KEY(purl, source)
);
```

At startup: `SELECT purl FROM cache GROUP BY purl HAVING COUNT(DISTINCT source)=4` → skip set. `--refresh` flag truncates the table. Per-purl failures are persisted (so we don't retry on resume) but cleared on `--refresh`.

### Merge function

`SIGNAL_MAP: dict[output_col, list[(source, dotted_path | callable)]]` — the per-source ordering encodes the priority. Example:

```python
SIGNAL_MAP = {
    "stars":    [("ecosystems", "repo_metadata.stargazers_count"),
                 ("github",     "stargazerCount"),
                 ("depsdev",    "scorecard.stars_count")],
    "snyk_max_cvss": [("snyk", "_agg.max_cvss")],
    "is_deprecated": [("depsdev",    "is_deprecated"),
                      ("ecosystems", lambda r: r["status"] == "deprecated")],
    # ...one entry per output column
}
```

Per-source aggregations (Snyk severity counts, ecosyste.ms advisory rollups) are computed once in the source module's `from_api` classmethod and surfaced under `_agg.*` so the map stays flat.

## Output columns (~58, in this order)

**Identity**: `purl_canonical`, `ecosystem`, `package_name`

**Release / activity**: `latest_version`, `latest_release_published_at`, `version_published_at`, `versions_count`, `is_default_version`, `last_repo_pushed_at`

**Popularity / usage**: `downloads`, `downloads_period`, `dependent_packages_count`, `dependent_repos_count`, `stars`, `forks`

**License & funding**: `licenses_spdx`, `funding_links`

**Deprecation**: `is_deprecated`, `deprecation_reason`, `package_status`

**Ecosyste.ms advisories**: `eco_advisories_count`, `eco_advisories_critical_count`, `eco_advisories_high_count`, `eco_max_cvss`, `eco_max_epss_percentile`, `eco_cve_ids`

**Snyk vulnerabilities**: `snyk_issues_total`, `snyk_critical_count`, `snyk_high_count`, `snyk_medium_count`, `snyk_low_count`, `snyk_max_cvss`, `snyk_exploit_mature`, `snyk_has_fix`, `snyk_license_issues`, `snyk_cve_ids`

**OpenSSF Scorecard** (priority: scorecard API > deps.dev): `scorecard_overall`, `scorecard_maintained`, `scorecard_code_review`, `scorecard_dangerous_workflow`, `scorecard_branch_protection`, `scorecard_pinned_dependencies`, `scorecard_vulnerabilities`, `scorecard_license`, `scorecard_signed_releases`, `scorecard_sast`, `scorecard_security_policy`, `scorecard_token_permissions`, `scorecard_contributors`

**GitHub repo**: `github_repo`, `github_watchers`, `github_open_issues`, `github_open_prs`, `github_releases_count`, `github_default_branch_last_commit_at`, `github_is_archived`, `github_is_disabled`, `github_primary_language`, `github_topics`, `github_health_percentage`, `github_total_commits`, `github_total_committers`

**Meta**: `_errors` (comma-joined source names that errored on this purl; empty when clean)

## API endpoints (locked from research)

| Source | Endpoint | Notes |
|---|---|---|
| deps.dev | `POST /v3alpha/purlbatch` (batch); `GET /v3alpha/purl/{quoted_purl}` (single); `GET /v3/projects/{repo}` (scorecard) | URL-encode whole purl as one segment; needs `@version` for batch |
| ecosyste.ms | `POST packages.ecosyste.ms/api/v1/packages/bulk_lookup?mailto=arik@aregev.com`; `GET advisories.ecosyste.ms/api/v1/advisories/lookup?purl=...` | Polite UA: `operational-metrics-script (arik@aregev.com)` |
| GitHub | `POST api.github.com/graphql` (aliased query of 25 repos); `GET /repos/{o}/{r}/community/profile` | Bearer `$GITHUB_TOKEN`; check `rateLimit.remaining` |
| Scorecard | `GET api.securityscorecards.dev/projects/github.com/{o}/{r}` | Anonymous; 404 → null record |
| Snyk | `GET api.snyk.io/rest/orgs/{SNYK_ORG_ID}/packages/{quoted_purl}/issues?version=2024-10-15` | `Authorization: token $SNYK_TOKEN` (lowercase `token`, NOT Bearer); paginate via `links.next` |

### Gotchas

- **deps.dev purl encoding**: whole purl as one path segment via `urllib.parse.quote(purl, safe="")`. Scoped npm like `pkg:npm/@scope/name@v` double-encodes the `@`.
- **Ecosystem casing**: deps.dev uses `NPM` (uppercase); ecosyste.ms uses `npm`. Normalize both to lowercase on output.
- **Versionless purls**: deps.dev `purlbatch` rejects them. Such rows fall back to ecosyste.ms only; `_errors` notes `depsdev:no_version`.
- **EPSS** is only in ecosyste.ms — required if you want exploit-probability scoring.
- **Snyk URL-encoding**: `:`, `/`, `@` all need encoding inside the path param.

## CLI

```
python -m enrich INPUT.csv -o OUTPUT.csv [--refresh] [--concurrency N] [--limit N]
```

- `INPUT.csv` — positional, must contain `purl_canonical` column
- `-o OUTPUT.csv` — required output path
- `--refresh` — wipe cache, re-fetch everything
- `--concurrency` — multiplier on default semaphores (default 1.0)
- `--limit N` — process only first N unique purls (smoke test)

`.env` in CWD is auto-loaded. Required vars validated at startup with clear error if missing.

## Verification

After implementation, run with this 8-purl smoke file covering all interesting shapes:

```csv
purl_canonical,note
pkg:npm/express@4.18.2,popular npm
pkg:npm/%40angular/core@17.0.0,scoped npm (encoded @)
pkg:pypi/requests@2.31.0,popular pypi
pkg:pypi/django@4.2.0,popular pypi with security history
pkg:maven/org.apache.commons/commons-lang3@3.12.0,maven groupId/artifactId
pkg:cargo/serde@1.0.193,cargo
pkg:golang/github.com/gin-gonic/gin@v1.9.1,golang
pkg:npm/left-pad@1.3.0,low-activity edge case
```

Expected assertions:
1. CSV has all ~58 columns in fixed order
2. ≥6 of 8 rows have non-null `scorecard_overall`
3. All 8 rows have non-null `purl_canonical`
4. `_errors` empty for at least 5 rows
5. `express` and `django` show non-zero `snyk_issues_total` (curated DB)
6. `left-pad` exercises graceful empty-scorecard path
7. `@angular/core` exercises URL-encoded scope
8. Re-running with no `--refresh` is a no-op (all data served from cache)

To verify:
```bash
cd /Users/arikregev/operational_metrics_script
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env  # then fill GITHUB_TOKEN, SNYK_TOKEN, SNYK_ORG_ID
python -m enrich tests/smoke.csv -o /tmp/out.csv --limit 8
column -t -s, /tmp/out.csv | less -S   # eyeball the output
python -m enrich tests/smoke.csv -o /tmp/out.csv --limit 8  # second run: cache hits, fast
```

## Critical files to create

- `/Users/arikregev/operational_metrics_script/pyproject.toml`
- `/Users/arikregev/operational_metrics_script/enrich/pipeline.py`
- `/Users/arikregev/operational_metrics_script/enrich/merge.py`
- `/Users/arikregev/operational_metrics_script/enrich/cache.py`
- `/Users/arikregev/operational_metrics_script/enrich/sources/depsdev.py`
- `/Users/arikregev/operational_metrics_script/enrich/sources/ecosystems.py`
- `/Users/arikregev/operational_metrics_script/enrich/sources/github.py`
- `/Users/arikregev/operational_metrics_script/enrich/sources/scorecard.py`
- `/Users/arikregev/operational_metrics_script/enrich/sources/snyk.py`
