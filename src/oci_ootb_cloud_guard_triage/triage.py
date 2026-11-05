"""Triage logic for Cloud Guard problem exports.

Cloud Guard (an out-of-the-box OCI security posture service) detects
"problems" against detector rules and can route them to responders. This
module works on a static JSON export of those problems: it groups OPEN
problems by detector rule, ranks them by severity, and attaches a recommended
remediation step for each known rule. All analysis is offline; no OCI calls.
"""

from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Recommended first remediation step per detector rule id (Oracle-managed
# recipe rule ids). Unknown rules fall back to a generic review step.
RECOMMENDATIONS = {
    "INSTANCE_SSH_PUBLIC_ACCESS": "Restrict SSH ingress to a bastion or corporate CIDRs; remove 0.0.0.0/0 from the security list or NSG",
    "PUBLIC_OBJECT_STORAGE_BUCKET": "Set the bucket to private and grant access through pre-authenticated requests or IAM policy",
    "ROOT_USER_ACTIVE_API_KEY": "Remove API keys from the root user; use a least-privileged IAM user or instance principal",
    "USER_NO_MFA": "Enforce multi-factor authentication for interactive IAM users",
    "LB_NO_SSL": "Attach an HTTPS listener with a valid certificate bundle and redirect HTTP traffic",
    "DB_SYSTEM_PUBLIC_ENDPOINT": "Move the database endpoint to a private subnet; expose it through a bastion or private endpoint",
    "VCN_FLOW_LOGS_DISABLED": "Enable VCN flow logs so network traffic can be investigated",
    "AUDIT_LOG_DISABLED": "Re-enable audit logging for the compartment before any further change",
}


@dataclass
class Problem:
    id: str
    detector_rule_id: str
    severity: str
    resource_name: str
    resource_type: str
    status: str


@dataclass
class RuleGroup:
    detector_rule_id: str
    worst_severity: str
    problems: list = field(default_factory=list)
    recommendation: str = ""

    @property
    def open_count(self):
        return sum(1 for p in self.problems if p.status == "OPEN")


def _parse_problem(raw):
    if not isinstance(raw, dict):
        raise ValueError("each problem entry must be an object")
    try:
        severity = raw["severity"].upper()
        status = raw["status"].upper()
        return Problem(
            id=str(raw["id"]),
            detector_rule_id=str(raw["detector_rule_id"]),
            severity=severity,
            resource_name=str(raw.get("resource_name", "<unknown>")),
            resource_type=str(raw.get("resource_type", "<unknown>")),
            status=status,
        )
    except KeyError as exc:
        raise ValueError(f"problem entry missing required field: {exc}") from exc


def load_problems(document):
    if not isinstance(document, dict) or not isinstance(document.get("problems"), list):
        raise ValueError("document must contain a top-level 'problems' list")
    problems = [_parse_problem(raw) for raw in document["problems"]]
    for problem in problems:
        if problem.severity not in SEVERITY_ORDER:
            raise ValueError(f"problem {problem.id} has unknown severity '{problem.severity}'")
        if problem.status not in ("OPEN", "RESOLVED", "DISMISSED"):
            raise ValueError(f"problem {problem.id} has unknown status '{problem.status}'")
    return problems


def group_open_problems(problems):
    """Group OPEN problems by detector rule, worst severity first."""
    groups = {}
    for problem in problems:
        if problem.status != "OPEN":
            continue
        group = groups.setdefault(
            problem.detector_rule_id,
            RuleGroup(detector_rule_id=problem.detector_rule_id, worst_severity=problem.severity),
        )
        group.problems.append(problem)
        if SEVERITY_ORDER[problem.severity] < SEVERITY_ORDER[group.worst_severity]:
            group.worst_severity = problem.severity
    for group in groups.values():
        group.recommendation = RECOMMENDATIONS.get(
            group.detector_rule_id,
            "Review the detector rule details in Cloud Guard and remediate the flagged configuration",
        )
    return sorted(groups.values(), key=lambda g: (SEVERITY_ORDER[g.worst_severity], g.detector_rule_id))


def severity_counts(problems, status="OPEN"):
    counts = {level: 0 for level in SEVERITY_ORDER}
    for problem in problems:
        if problem.status == status:
            counts[problem.severity] += 1
    return counts
