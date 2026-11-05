#!/bin/sh
# Triage the seeded export (open CRITICAL/HIGH -> exit 2), then the remediated export.
set -u
export PYTHONPATH="$(dirname "$0")/src"

echo "=== Triaging samples/cloud-guard-problems.json ==="
python3 -m oci_ootb_cloud_guard_triage samples/cloud-guard-problems.json
echo "exit code: $? (2 = open CRITICAL/HIGH problems, expected for the seeded export)"
echo
echo "=== Triaging samples/cloud-guard-problems-clean.json ==="
python3 -m oci_ootb_cloud_guard_triage samples/cloud-guard-problems-clean.json
echo "exit code: $? (0 = no open CRITICAL/HIGH problems, expected after remediation)"
