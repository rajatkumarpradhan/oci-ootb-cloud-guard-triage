import unittest

from oci_ootb_cloud_guard_triage.triage import (
    RECOMMENDATIONS,
    group_open_problems,
    load_problems,
    severity_counts,
)


def problem(pid, rule, severity, status="OPEN"):
    return {
        "id": pid,
        "detector_rule_id": rule,
        "severity": severity,
        "resource_name": f"res-{pid}",
        "resource_type": "INSTANCE",
        "status": status,
    }


class TestLoadProblems(unittest.TestCase):
    def test_valid_document_loads(self):
        problems = load_problems({"problems": [problem("p1", "LB_NO_SSL", "HIGH")]})
        self.assertEqual(len(problems), 1)
        self.assertEqual(problems[0].severity, "HIGH")

    def test_missing_problems_list_rejected(self):
        with self.assertRaises(ValueError):
            load_problems({"items": []})

    def test_non_object_entry_rejected(self):
        with self.assertRaises(ValueError):
            load_problems({"problems": ["junk"]})

    def test_missing_field_rejected(self):
        bad = problem("p1", "LB_NO_SSL", "HIGH")
        del bad["severity"]
        with self.assertRaises(ValueError):
            load_problems({"problems": [bad]})

    def test_unknown_severity_rejected(self):
        with self.assertRaises(ValueError):
            load_problems({"problems": [problem("p1", "LB_NO_SSL", "SEVERE")]})

    def test_unknown_status_rejected(self):
        with self.assertRaises(ValueError):
            load_problems({"problems": [problem("p1", "LB_NO_SSL", "HIGH", status="MAYBE")]})

    def test_case_normalised(self):
        raw = problem("p1", "LB_NO_SSL", "high", status="open")
        problems = load_problems({"problems": [raw]})
        self.assertEqual(problems[0].severity, "HIGH")
        self.assertEqual(problems[0].status, "OPEN")


class TestGrouping(unittest.TestCase):
    def setUp(self):
        self.problems = load_problems({"problems": [
            problem("p1", "INSTANCE_SSH_PUBLIC_ACCESS", "CRITICAL"),
            problem("p2", "INSTANCE_SSH_PUBLIC_ACCESS", "HIGH"),
            problem("p3", "INSTANCE_SSH_PUBLIC_ACCESS", "CRITICAL", status="RESOLVED"),
            problem("p4", "VCN_FLOW_LOGS_DISABLED", "MEDIUM"),
        ]})

    def test_only_open_problems_grouped(self):
        groups = group_open_problems(self.problems)
        ssh = next(g for g in groups if g.detector_rule_id == "INSTANCE_SSH_PUBLIC_ACCESS")
        self.assertEqual(ssh.open_count, 2)

    def test_groups_sorted_worst_first(self):
        groups = group_open_problems(self.problems)
        self.assertEqual(groups[0].worst_severity, "CRITICAL")
        self.assertEqual(groups[1].worst_severity, "MEDIUM")

    def test_worst_severity_within_group(self):
        groups = group_open_problems(self.problems)
        ssh = next(g for g in groups if g.detector_rule_id == "INSTANCE_SSH_PUBLIC_ACCESS")
        self.assertEqual(ssh.worst_severity, "CRITICAL")

    def test_known_rule_has_specific_recommendation(self):
        groups = group_open_problems(self.problems)
        ssh = next(g for g in groups if g.detector_rule_id == "INSTANCE_SSH_PUBLIC_ACCESS")
        self.assertEqual(ssh.recommendation, RECOMMENDATIONS["INSTANCE_SSH_PUBLIC_ACCESS"])

    def test_unknown_rule_gets_fallback_recommendation(self):
        problems = load_problems({"problems": [problem("p9", "SOME_FUTURE_RULE", "LOW")]})
        group = group_open_problems(problems)[0]
        self.assertIn("Cloud Guard", group.recommendation)

    def test_empty_when_nothing_open(self):
        problems = load_problems({"problems": [
            problem("p1", "LB_NO_SSL", "HIGH", status="RESOLVED"),
            problem("p2", "USER_NO_MFA", "MEDIUM", status="DISMISSED"),
        ]})
        self.assertEqual(group_open_problems(problems), [])


class TestSeverityCounts(unittest.TestCase):
    def test_counts_only_requested_status(self):
        problems = load_problems({"problems": [
            problem("p1", "A", "CRITICAL"),
            problem("p2", "A", "CRITICAL", status="RESOLVED"),
            problem("p3", "B", "LOW"),
        ]})
        counts = severity_counts(problems)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["HIGH"], 0)


if __name__ == "__main__":
    unittest.main()
