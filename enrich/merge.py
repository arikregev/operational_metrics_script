"""Output schema + merge logic.

``COLUMNS`` is the ordered CSV header. ``SIGNAL_MAP`` defines, per output
column, the ordered list of (source, lookup) entries to consult — the first
non-empty value wins. ``lookup`` is either a dotted-path string into the
source's normalized record dict, or a callable that takes the dict and returns
the value.

Priority order across sources (user-confirmed): ecosystems > depsdev > github > snyk.
Scorecard API takes priority over deps.dev's snapshotted scorecard fields.
"""
from __future__ import annotations

from typing import Any, Callable, Union

from enrich.types import SourceName, SourceRecord

Lookup = Union[str, Callable[[SourceRecord], Any]]
SignalEntry = tuple[SourceName, Lookup]


def _dig(rec: SourceRecord | None, path: str) -> Any:
    if rec is None:
        return None
    cur: Any = rec
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def _check(name: str) -> Callable[[SourceRecord], Any]:
    def _fn(rec: SourceRecord) -> Any:
        checks = _dig(rec, "checks")
        if isinstance(checks, dict):
            return checks.get(name)
        return None

    _fn.__name__ = f"check_{name}"
    return _fn


def _depsdev_check(name: str) -> Callable[[SourceRecord], Any]:
    def _fn(rec: SourceRecord) -> Any:
        return _dig(rec, f"project.scorecard.checks.{name}")

    _fn.__name__ = f"depsdev_check_{name}"
    return _fn


def _join(path: str, sep: str = ";") -> Callable[[SourceRecord], Any]:
    def _fn(rec: SourceRecord) -> Any:
        v = _dig(rec, path)
        if not v:
            return None
        if isinstance(v, (list, tuple, set)):
            return sep.join(str(x) for x in v if x)
        return v

    _fn.__name__ = f"join_{path}"
    return _fn


def _eco_deprecated(rec: SourceRecord) -> Any:
    status = (rec.get("status") or "").lower() if isinstance(rec, dict) else ""
    if status == "deprecated":
        return True
    if status in ("active", "available"):
        return False
    return None


def _package_name_from_purl(purl: str) -> str:
    # pkg:npm/lodash@4.17.21 -> lodash ; pkg:maven/g/a@1 -> g/a
    if not purl.startswith("pkg:"):
        return purl
    body = purl[4:]
    type_sep = body.find("/")
    after_type = body[type_sep + 1 :] if type_sep != -1 else body
    at = after_type.rfind("@")
    return after_type[:at] if at != -1 else after_type


SIGNAL_MAP: dict[str, list[SignalEntry]] = {
    # ----- Identity -----
    "ecosystem": [
        ("ecosystems", "ecosystem"),
        ("depsdev", "version_key.system"),
    ],
    "package_name": [
        ("ecosystems", "name"),
        ("depsdev", "version_key.name"),
    ],
    # ----- Release / activity -----
    "latest_version": [
        ("ecosystems", "latest_release_number"),
    ],
    "latest_release_published_at": [
        ("ecosystems", "latest_release_published_at"),
        ("github", "latest_release_at"),
    ],
    "version_published_at": [
        ("depsdev", "published_at"),
    ],
    "versions_count": [
        ("ecosystems", "versions_count"),
    ],
    "is_default_version": [
        ("depsdev", "is_default"),
    ],
    "last_repo_pushed_at": [
        ("ecosystems", "repo_metadata.pushed_at"),
        ("github", "pushed_at"),
    ],
    # ----- Popularity / usage -----
    "downloads": [
        ("ecosystems", "downloads"),
    ],
    "downloads_period": [
        ("ecosystems", "downloads_period"),
    ],
    "dependent_packages_count": [
        ("ecosystems", "dependent_packages_count"),
    ],
    "dependent_repos_count": [
        ("ecosystems", "dependent_repos_count"),
    ],
    "stars": [
        ("ecosystems", "repo_metadata.stargazers_count"),
        ("depsdev", "project.stars_count"),
        ("github", "stars"),
    ],
    "forks": [
        ("ecosystems", "repo_metadata.forks_count"),
        ("depsdev", "project.forks_count"),
        ("github", "forks"),
    ],
    # ----- License & funding -----
    "licenses_spdx": [
        ("ecosystems", _join("normalized_licenses")),
        ("depsdev", _join("licenses")),
        ("github", "license_spdx"),
    ],
    "funding_links": [
        ("ecosystems", _join("funding_links")),
    ],
    # ----- Deprecation -----
    "is_deprecated": [
        ("depsdev", "is_deprecated"),
        ("ecosystems", _eco_deprecated),
    ],
    "deprecation_reason": [
        ("depsdev", "deprecation_reason"),
    ],
    "package_status": [
        ("ecosystems", "status"),
    ],
    # ----- Ecosyste.ms advisories -----
    "eco_advisories_count": [("ecosystems", "_agg.count")],
    "eco_advisories_critical_count": [("ecosystems", "_agg.critical")],
    "eco_advisories_high_count": [("ecosystems", "_agg.high")],
    "eco_max_cvss": [("ecosystems", "_agg.max_cvss")],
    "eco_max_epss_percentile": [("ecosystems", "_agg.max_epss_percentile")],
    "eco_cve_ids": [("ecosystems", _join("_agg.cve_ids"))],
    # ----- Snyk -----
    "snyk_issues_total": [("snyk", "_agg.total")],
    "snyk_critical_count": [("snyk", "_agg.critical")],
    "snyk_high_count": [("snyk", "_agg.high")],
    "snyk_medium_count": [("snyk", "_agg.medium")],
    "snyk_low_count": [("snyk", "_agg.low")],
    "snyk_max_cvss": [("snyk", "_agg.max_cvss")],
    "snyk_exploit_mature": [("snyk", "_agg.exploit_mature")],
    "snyk_has_fix": [("snyk", "_agg.has_fix")],
    "snyk_license_issues": [("snyk", "_agg.license_issues")],
    "snyk_cve_ids": [("snyk", _join("_agg.cve_ids"))],
    # ----- OpenSSF Scorecard (scorecard API > depsdev) -----
    "scorecard_overall": [
        ("scorecard", "score"),
        ("depsdev", "project.scorecard.overall_score"),
    ],
    "scorecard_maintained": [
        ("scorecard", _check("Maintained")),
        ("depsdev", _depsdev_check("Maintained")),
    ],
    "scorecard_code_review": [
        ("scorecard", _check("Code-Review")),
        ("depsdev", _depsdev_check("Code-Review")),
    ],
    "scorecard_dangerous_workflow": [
        ("scorecard", _check("Dangerous-Workflow")),
        ("depsdev", _depsdev_check("Dangerous-Workflow")),
    ],
    "scorecard_branch_protection": [
        ("scorecard", _check("Branch-Protection")),
        ("depsdev", _depsdev_check("Branch-Protection")),
    ],
    "scorecard_pinned_dependencies": [
        ("scorecard", _check("Pinned-Dependencies")),
        ("depsdev", _depsdev_check("Pinned-Dependencies")),
    ],
    "scorecard_vulnerabilities": [
        ("scorecard", _check("Vulnerabilities")),
        ("depsdev", _depsdev_check("Vulnerabilities")),
    ],
    "scorecard_license": [
        ("scorecard", _check("License")),
        ("depsdev", _depsdev_check("License")),
    ],
    "scorecard_signed_releases": [
        ("scorecard", _check("Signed-Releases")),
        ("depsdev", _depsdev_check("Signed-Releases")),
    ],
    "scorecard_sast": [
        ("scorecard", _check("SAST")),
        ("depsdev", _depsdev_check("SAST")),
    ],
    "scorecard_security_policy": [
        ("scorecard", _check("Security-Policy")),
        ("depsdev", _depsdev_check("Security-Policy")),
    ],
    "scorecard_token_permissions": [
        ("scorecard", _check("Token-Permissions")),
        ("depsdev", _depsdev_check("Token-Permissions")),
    ],
    "scorecard_contributors": [
        ("scorecard", _check("Contributors")),
        ("depsdev", _depsdev_check("Contributors")),
    ],
    # ----- GitHub repo -----
    "github_repo": [("depsdev", "github_repo")],
    "github_watchers": [("github", "watchers")],
    "github_open_issues": [
        ("github", "open_issues"),
        ("ecosystems", "repo_metadata.open_issues_count"),
    ],
    "github_open_prs": [("github", "open_prs")],
    "github_releases_count": [("github", "releases_count")],
    "github_default_branch_last_commit_at": [("github", "default_branch_last_commit_at")],
    "github_is_archived": [
        ("github", "is_archived"),
        ("ecosystems", "repo_metadata.archived"),
    ],
    "github_is_disabled": [("github", "is_disabled")],
    "github_primary_language": [("github", "primary_language")],
    "github_topics": [("github", _join("topics"))],
    "github_health_percentage": [("github", "community.health_percentage")],
    "github_total_commits": [("ecosystems", "repo_metadata.total_commits")],
    "github_total_committers": [("ecosystems", "repo_metadata.total_committers")],
}


COLUMNS: list[str] = [
    "purl_canonical",
    # Identity
    "ecosystem",
    "package_name",
    # Release / activity
    "latest_version",
    "latest_release_published_at",
    "version_published_at",
    "versions_count",
    "is_default_version",
    "last_repo_pushed_at",
    # Popularity
    "downloads",
    "downloads_period",
    "dependent_packages_count",
    "dependent_repos_count",
    "stars",
    "forks",
    # License & funding
    "licenses_spdx",
    "funding_links",
    # Deprecation
    "is_deprecated",
    "deprecation_reason",
    "package_status",
    # Ecosyste.ms advisories
    "eco_advisories_count",
    "eco_advisories_critical_count",
    "eco_advisories_high_count",
    "eco_max_cvss",
    "eco_max_epss_percentile",
    "eco_cve_ids",
    # Snyk
    "snyk_issues_total",
    "snyk_critical_count",
    "snyk_high_count",
    "snyk_medium_count",
    "snyk_low_count",
    "snyk_max_cvss",
    "snyk_exploit_mature",
    "snyk_has_fix",
    "snyk_license_issues",
    "snyk_cve_ids",
    # OpenSSF Scorecard
    "scorecard_overall",
    "scorecard_maintained",
    "scorecard_code_review",
    "scorecard_dangerous_workflow",
    "scorecard_branch_protection",
    "scorecard_pinned_dependencies",
    "scorecard_vulnerabilities",
    "scorecard_license",
    "scorecard_signed_releases",
    "scorecard_sast",
    "scorecard_security_policy",
    "scorecard_token_permissions",
    "scorecard_contributors",
    # GitHub repo
    "github_repo",
    "github_watchers",
    "github_open_issues",
    "github_open_prs",
    "github_releases_count",
    "github_default_branch_last_commit_at",
    "github_is_archived",
    "github_is_disabled",
    "github_primary_language",
    "github_topics",
    "github_health_percentage",
    "github_total_commits",
    "github_total_committers",
    # Meta
    "_errors",
]


def _empty(v: Any) -> bool:
    return v is None or v == "" or v == [] or v == {}


def merge(
    purl: str,
    records: dict[SourceName, tuple[SourceRecord | None, str]],
) -> dict[str, Any]:
    """Build the flat output row by priority-filling each column from records."""
    out: dict[str, Any] = {"purl_canonical": purl}
    errors: list[str] = []
    for src, (_, status) in records.items():
        if status and not (status == "ok" or status == "no_repo"):
            errors.append(f"{src}:{status}")

    for col, entries in SIGNAL_MAP.items():
        value: Any = None
        for src, lookup in entries:
            rec_tuple = records.get(src)
            if rec_tuple is None:
                continue
            rec, status = rec_tuple
            if rec is None or status not in ("ok",):
                continue
            v = lookup(rec) if callable(lookup) else _dig(rec, lookup)
            if not _empty(v):
                value = v
                break
        out[col] = value

    # Fallback package_name from the purl itself.
    if _empty(out.get("package_name")):
        out["package_name"] = _package_name_from_purl(purl)

    out["_errors"] = ",".join(errors)
    return out
