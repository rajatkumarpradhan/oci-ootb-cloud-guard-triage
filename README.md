# oci-ootb-cloud-guard-triage

An out-of-the-box OCI security workflow: **enable Cloud Guard on a compartment, then triage the problems it finds**. Cloud Guard is OCI's built-in security posture service - Oracle-managed detector recipes flag misconfigurations as "problems" without any custom detection code. This repo wires the built-in part (Terraform) and adds the missing operational part: a local triage reporter that turns a raw problem export into a ranked, actionable list.

## What it is

Two pieces:

1. **`infra/main.tf`** - Terraform template that enables Cloud Guard on a compartment: clones the Oracle-managed configuration detector recipe and creates a Cloud Guard target so problems start appearing for that compartment tree.
2. **`src/`** - an offline triage CLI. It reads a static JSON export of Cloud Guard problems, groups the OPEN ones by detector rule, ranks groups by worst severity, attaches a concrete first remediation step for each known rule, and exits 2 when CRITICAL/HIGH problems remain open - usable as a daily posture gate.

## What it is NOT (honest limits)

- The Terraform template has **not** been plan/apply validated against a tenancy. It is a structural starting point; review it against the current OCI provider docs before any real apply.
- The triage CLI consumes a **static JSON export** (schema below, a simplification of the Cloud Guard problem fields). It does not call the OCI API; producing that export from a real tenancy is out of scope here.
- Remediation recommendations are fixed guidance per detector rule id from a built-in map; unknown rules get a generic review step. They are starting points, not verified fixes.
- CRITICAL/HIGH as blocking severities is a local convention, not a Cloud Guard concept.
- The reporter does not simulate Cloud Guard's responder recipes, notification cadence, or problem lifecycle transitions; it reports on the export as given.
- No live resources, cost, emails, or tenancy data are involved in any run of this repo.

## Input schema

```json
{
  "problems": [
    {
      "id": "prob-1001",
      "detector_rule_id": "INSTANCE_SSH_PUBLIC_ACCESS",
      "severity": "CRITICAL",
      "resource_name": "web-tier-1",
      "resource_type": "INSTANCE",
      "status": "OPEN",
      "first_detected": "2026-11-05T14:22:10Z"
    }
  ]
}
```

`severity` must be one of CRITICAL/HIGH/MEDIUM/LOW; `status` one of OPEN/RESOLVED/DISMISSED. Only OPEN problems are triaged.

## Run

Requires Python 3.10+, no third-party dependencies.

```sh
PYTHONPATH=src python3 -m oci_ootb_cloud_guard_triage samples/cloud-guard-problems.json
PYTHONPATH=src python3 -m oci_ootb_cloud_guard_triage samples/cloud-guard-problems-clean.json
```

Or the end-to-end demo (seeded export -> remediated export, with expected exit codes):

```sh
sh demo.sh
```

Expected demo output: the seeded export lists 4 open problems across 3 detector rules (worst CRITICAL) and exits 2; the remediated export has no open CRITICAL/HIGH and exits 0.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

18 unit tests cover export validation, severity/status handling, grouping and ranking, recommendation mapping (known and unknown rules), status filtering, and CLI exit codes. CI runs the same tests plus the demo on Python 3.10/3.11/3.12.
