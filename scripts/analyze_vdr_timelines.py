#!/usr/bin/env python3
"""Compare legacy CVSS remediation timelines with FedRAMP VDR timelines.

Legacy SLA is fixed by policy:
- CRITICAL/HIGH: 30 days
- MEDIUM/MODERATE: 90 days
- LOW: 180 days
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LEGACY_DAYS_BY_SEVERITY = {
    "CRITICAL": 30,
    "HIGH": 30,
    "MEDIUM": 90,
    "MODERATE": 90,
    "LOW": 180,
}


@dataclass(frozen=True)
class TimelineRow:
    cve_id: str
    title: str
    severity: str
    legacy_days: int
    vdr_days: int
    pain_tier: str
    remediation_column: str
    lev: bool
    irv: bool
    resource: str

    @property
    def delta_days(self) -> int:
        return self.vdr_days - self.legacy_days


def load_findings(path: Path) -> list[dict[str, Any]]:
    with path.open() as handle:
        document = json.load(handle)

    findings = document.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{path} does not contain a top-level findings list")

    return findings


def format_resource(resource: dict[str, Any] | None) -> str:
    if not resource:
        return ""

    parts = [
        resource.get("namespace"),
        resource.get("kind"),
        resource.get("name"),
        resource.get("containerName"),
    ]
    return "/".join(str(part) for part in parts if part)


def remediation_targets(finding: dict[str, Any], *, affected_resources: bool) -> list[dict[str, Any]]:
    if affected_resources:
        affected = finding.get("affected") or []
        if affected:
            return affected

    return [
        {
            "pain": finding.get("pain") or {},
            "remediation": finding.get("remediation") or {},
            "resource": None,
        }
    ]


def collect_rows(
    findings: list[dict[str, Any]],
    *,
    affected_resources: bool,
    include_no_clock: bool = False,
) -> list[TimelineRow]:
    rows: list[TimelineRow] = []

    for finding in findings:
        severity = str(finding.get("severity") or "").upper()
        legacy_days = LEGACY_DAYS_BY_SEVERITY.get(severity)
        if legacy_days is None:
            continue

        for target in remediation_targets(finding, affected_resources=affected_resources):
            remediation = target.get("remediation") or {}
            vdr_days = remediation.get("deadlineDays")
            if not isinstance(vdr_days, int):
                continue
            if vdr_days <= 0 and not include_no_clock:
                continue

            pain = target.get("pain") or {}
            rows.append(
                TimelineRow(
                    cve_id=str(finding.get("id") or ""),
                    title=str(finding.get("title") or ""),
                    severity=severity,
                    legacy_days=legacy_days,
                    vdr_days=vdr_days,
                    pain_tier=str(pain.get("tier") or ""),
                    remediation_column=str(remediation.get("column") or ""),
                    lev=bool(remediation.get("lev")),
                    irv=bool(remediation.get("irv")),
                    resource=format_resource(target.get("resource")),
                )
            )

    return rows


def mean(values: list[int]) -> float:
    return statistics.mean(values) if values else 0.0


def median(values: list[int]) -> float:
    return statistics.median(values) if values else 0.0


def pct(count: int, total: int) -> str:
    if not total:
        return "0.0%"
    return f"{count / total * 100:.1f}%"


def markdown_table(headers: list[str], rows: list[list[str | int | float]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def summary_row(label: str, rows: list[TimelineRow]) -> list[str | int | float]:
    deltas = [row.delta_days for row in rows]
    faster = sum(delta < 0 for delta in deltas)
    slower = sum(delta > 0 for delta in deltas)
    same = sum(delta == 0 for delta in deltas)

    return [
        label,
        len(rows),
        f"{mean([row.legacy_days for row in rows]):.1f}",
        f"{mean([row.vdr_days for row in rows]):.1f}",
        f"{mean(deltas):.1f}",
        f"{median([row.legacy_days for row in rows]):.1f}",
        f"{median([row.vdr_days for row in rows]):.1f}",
        faster,
        pct(faster, len(rows)),
        same,
        slower,
        pct(slower, len(rows)),
    ]


def severity_rows(rows: list[TimelineRow]) -> list[list[str | int]]:
    output = []
    for severity in LEGACY_DAYS_BY_SEVERITY:
        group = [row for row in rows if row.severity == severity]
        if not group:
            continue
        output.append(
            [
                severity,
                len(group),
                f"{mean([row.legacy_days for row in group]):.1f}",
                f"{mean([row.vdr_days for row in group]):.1f}",
                f"{mean([row.delta_days for row in group]):.1f}",
                sum(row.delta_days < 0 for row in group),
                sum(row.delta_days > 0 for row in group),
            ]
        )
    return output


def group_rows(rows: list[TimelineRow], attr: str, order: list[str] | None = None) -> list[list[str | int]]:
    groups: dict[str, list[TimelineRow]] = defaultdict(list)
    for row in rows:
        groups[str(getattr(row, attr))].append(row)

    keys = order or sorted(groups)
    output = []
    for key in keys:
        group = groups.get(key)
        if not group:
            continue
        output.append(
            [
                key,
                len(group),
                f"{mean([row.legacy_days for row in group]):.1f}",
                f"{mean([row.vdr_days for row in group]):.1f}",
                f"{mean([row.delta_days for row in group]):.1f}",
            ]
        )
    return output


def unique_cve_rows(rows: list[TimelineRow]) -> list[TimelineRow]:
    by_cve: dict[str, list[TimelineRow]] = defaultdict(list)
    for row in rows:
        by_cve[row.cve_id].append(row)

    unique_rows = []
    for cve_rows in by_cve.values():
        strictest = min(cve_rows, key=lambda row: row.vdr_days)
        legacy_days = min(row.legacy_days for row in cve_rows)
        unique_rows.append(
            TimelineRow(
                cve_id=strictest.cve_id,
                title=strictest.title,
                severity=strictest.severity,
                legacy_days=legacy_days,
                vdr_days=strictest.vdr_days,
                pain_tier=strictest.pain_tier,
                remediation_column=strictest.remediation_column,
                lev=strictest.lev,
                irv=strictest.irv,
                resource=strictest.resource,
            )
        )

    return unique_rows


def top_shift_rows(rows: list[TimelineRow], *, reverse: bool) -> list[list[str | int]]:
    output = []
    for row in sorted(rows, key=lambda item: item.delta_days, reverse=reverse)[:10]:
        output.append(
            [
                row.delta_days,
                row.cve_id,
                row.severity,
                f"{row.legacy_days} -> {row.vdr_days}",
                row.pain_tier,
                row.remediation_column,
                row.title[:100],
            ]
        )
    return output


def no_clock_summary(rows: list[TimelineRow]) -> list[list[str | int]]:
    counter = Counter((row.severity, row.pain_tier, row.remediation_column) for row in rows if row.vdr_days <= 0)
    return [[severity, tier, column, count] for (severity, tier, column), count in counter.most_common()]


def print_report(path: Path) -> None:
    findings = load_findings(path)
    affected_rows = collect_rows(findings, affected_resources=True)
    top_level_rows = collect_rows(findings, affected_resources=False)
    rows_with_no_clock = collect_rows(findings, affected_resources=True, include_no_clock=True)
    no_clock_rows = [row for row in rows_with_no_clock if row.vdr_days <= 0]
    unique_rows = unique_cve_rows(affected_rows)

    print(f"# VDR Timeline Comparison: `{path}`")
    print()
    print("Legacy SLA: CRITICAL/HIGH = 30 days, MEDIUM/MODERATE = 90 days, LOW = 180 days.")
    print("Rows with `deadlineDays <= 0` are treated as no prescribed VDR clock and excluded from deadline averages.")
    print()

    print("## Summary")
    print(
        markdown_table(
            [
                "View",
                "Rows",
                "Legacy Avg",
                "VDR Avg",
                "Avg Shift",
                "Legacy Median",
                "VDR Median",
                "Faster",
                "Faster %",
                "Same",
                "Slower",
                "Slower %",
            ],
            [
                summary_row("Affected resources", affected_rows),
                summary_row("Top-level findings", top_level_rows),
                summary_row("Unique CVEs, strictest VDR clock", unique_rows),
            ],
        )
    )
    print()

    print("## By Severity")
    print(markdown_table(["Severity", "Rows", "Legacy Avg", "VDR Avg", "Avg Shift", "Faster", "Slower"], severity_rows(affected_rows)))
    print()

    print("## By VDR PAIN Tier")
    print(markdown_table(["PAIN Tier", "Rows", "Legacy Avg", "VDR Avg", "Avg Shift"], group_rows(affected_rows, "pain_tier", ["N5", "N4", "N3", "N2"])))
    print()

    print("## By Remediation Column")
    print(markdown_table(["Column", "Rows", "Legacy Avg", "VDR Avg", "Avg Shift"], group_rows(affected_rows, "remediation_column")))
    print()

    print("## VDR Deadline Buckets")
    print(markdown_table(["Deadline Days", "Rows"], [[days, count] for days, count in Counter(row.vdr_days for row in affected_rows).most_common()]))
    print()

    print("## No Prescribed VDR Clock")
    if no_clock_rows:
        print(markdown_table(["Severity", "PAIN Tier", "Column", "Rows"], no_clock_summary(rows_with_no_clock)))
    else:
        print("No rows with `deadlineDays <= 0`.")
    print()

    print("## Most Accelerated Unique CVEs")
    print(markdown_table(["Shift", "CVE", "Severity", "Days", "PAIN", "Column", "Title"], top_shift_rows(unique_rows, reverse=False)))
    print()

    print("## Most Relaxed Unique CVEs")
    print(markdown_table(["Shift", "CVE", "Severity", "Days", "PAIN", "Column", "Title"], top_shift_rows(unique_rows, reverse=True)))
    print()

    irv_count = sum(row.irv for row in affected_rows)
    lev_irv_count = sum(row.irv and row.lev for row in affected_rows)
    print("## IRV/LEV Note")
    print(
        f"{irv_count} affected-resource rows were internet-reachable; {lev_irv_count} were both LEV and IRV. "
        "Under FedRAMP's PVR matrix, IRV shortens the remediation clock only when paired with LEV."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_path", type=Path, help="Path to a Rally VDR JSON export")
    args = parser.parse_args()
    print_report(args.json_path)


if __name__ == "__main__":
    main()
