"""Command line interface for the Cloud Guard triage reporter."""

import argparse
import json
import sys

from .triage import SEVERITY_ORDER, group_open_problems, load_problems, severity_counts

EXIT_BLOCKING_FINDINGS = 2
EXIT_INPUT_ERROR = 1
EXIT_OK = 0

# Severities treated as blocking for the exit code (local convention).
BLOCKING_SEVERITIES = ("CRITICAL", "HIGH")


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc


def _render(problems, groups):
    lines = []
    if not groups:
        lines.append("No OPEN Cloud Guard problems in this export.")
    for group in groups:
        lines.append(
            f"[{group.worst_severity:<8}] {group.detector_rule_id} - {group.open_count} open problem(s)"
        )
        lines.append(f"  fix: {group.recommendation}")
        for problem in group.problems:
            lines.append(
                f"  - {problem.id} [{problem.severity}] {problem.resource_type}/{problem.resource_name}"
            )
    counts = severity_counts(problems)
    lines.append(
        "summary: {critical} critical, {high} high, {medium} medium, {low} low open problem(s)".format(
            critical=counts["CRITICAL"], high=counts["HIGH"],
            medium=counts["MEDIUM"], low=counts["LOW"],
        )
    )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="oci-ootb-cloud-guard-triage",
        description="Offline triage report for OCI Cloud Guard problem exports.",
    )
    parser.add_argument("path", help="Cloud Guard problems JSON export")
    args = parser.parse_args(argv)

    try:
        problems = load_problems(_load(args.path))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    groups = group_open_problems(problems)
    print(_render(problems, groups))
    counts = severity_counts(problems)
    if any(counts[level] > 0 for level in BLOCKING_SEVERITIES):
        return EXIT_BLOCKING_FINDINGS
    return EXIT_OK
