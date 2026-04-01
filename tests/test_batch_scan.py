import unittest

from _bootstrap import PROJECT_ROOT  # noqa: F401
from core.batch_scan import BatchScanRunner


class BatchScanRunnerTests(unittest.TestCase):
    def test_build_item_summary_for_success(self):
        summary = BatchScanRunner.build_item_summary(
            domain="example.com",
            result={
                "subdomains": [{"subdomain": "www.example.com", "ip": ["1.1.1.1"]}],
                "wildcard": {"detected": False},
                "statistics": {"total_found": 3},
                "tool_runs": {
                    "subfinder": {
                        "status": "completed",
                        "return_code": 0,
                        "message": "ok",
                        "raw_count": 3,
                        "valid_count": 3,
                    }
                },
            },
            saved_path=None,
        )

        self.assertEqual(summary["status"], "success")
        self.assertEqual(summary["valid_count"], 1)
        self.assertEqual(summary["total_found"], 3)
        self.assertFalse(summary["wildcard_detected"])
        self.assertEqual(summary["web_fingerprint_status"], "not_started")
        self.assertEqual(summary["web_target_count"], 0)
        self.assertEqual(summary["directory_scan_status"], "not_started")
        self.assertEqual(summary["dirsearch_finding_count"], 0)

    def test_build_item_summary_for_wildcard_result(self):
        summary = BatchScanRunner.build_item_summary(
            domain="example.com",
            result={
                "subdomains": [],
                "wildcard": {"detected": True},
                "statistics": {"total_found": 5},
                "tool_runs": {
                    "subfinder": {
                        "status": "completed",
                        "return_code": 0,
                        "message": "ok",
                        "raw_count": 5,
                        "valid_count": 0,
                    }
                },
            },
            saved_path=None,
        )

        self.assertEqual(summary["status"], "no_valid_results")
        self.assertTrue(summary["wildcard_detected"])
        self.assertIn("泛解析", summary["message"])

    def test_build_item_summary_marks_all_tool_failures_as_error(self):
        summary = BatchScanRunner.build_item_summary(
            domain="example.com",
            result={
                "subdomains": [],
                "wildcard": {"detected": False},
                "statistics": {"total_found": 0},
                "tool_runs": {
                    "subfinder": {
                        "status": "error",
                        "return_code": 1,
                        "message": "boom",
                        "raw_count": 0,
                        "valid_count": 0,
                    },
                    "oneforall": {
                        "status": "timeout",
                        "return_code": None,
                        "message": "timeout",
                        "raw_count": 0,
                        "valid_count": 0,
                    },
                },
            },
            saved_path=None,
        )

        self.assertEqual(summary["status"], "error")
        self.assertIn("执行失败", summary["message"])

    def test_build_summary_counts_statuses(self):
        summary = BatchScanRunner.build_summary(
            summary_items=[
                {
                    "domain": "a.com",
                    "status": "success",
                    "message": "ok",
                    "saved_path": None,
                    "valid_count": 2,
                    "total_found": 3,
                    "wildcard_detected": False,
                    "tool_runs": {},
                    "port_scan_status": "completed",
                    "open_port_count": 4,
                    "web_fingerprint_status": "completed",
                    "web_target_count": 2,
                    "directory_scan_status": "completed",
                    "dirsearch_finding_count": 3,
                },
                {
                    "domain": "b.com",
                    "status": "no_valid_results",
                    "message": "none",
                    "saved_path": None,
                    "valid_count": 0,
                    "total_found": 0,
                    "wildcard_detected": False,
                    "tool_runs": {},
                    "port_scan_status": "not_started",
                    "open_port_count": 0,
                    "web_fingerprint_status": "not_started",
                    "web_target_count": 0,
                    "directory_scan_status": "not_started",
                    "dirsearch_finding_count": 0,
                },
                {
                    "domain": "c.com",
                    "status": "error",
                    "message": "boom",
                    "saved_path": None,
                    "valid_count": 0,
                    "total_found": 0,
                    "wildcard_detected": False,
                    "tool_runs": {},
                    "port_scan_status": "not_started",
                    "open_port_count": 0,
                    "web_fingerprint_status": "error",
                    "web_target_count": 0,
                    "directory_scan_status": "not_started",
                    "dirsearch_finding_count": 0,
                },
            ],
            tools=["subfinder", "oneforall"],
        )

        self.assertEqual(summary["statistics"]["total_domains"], 3)
        self.assertEqual(summary["statistics"]["success_count"], 1)
        self.assertEqual(summary["statistics"]["error_count"], 1)
        self.assertEqual(summary["statistics"]["no_valid_result_count"], 1)
        self.assertEqual(summary["statistics"]["port_scan_completed_count"], 1)
        self.assertEqual(summary["statistics"]["total_open_ports"], 4)
        self.assertEqual(summary["statistics"]["web_fingerprint_completed_count"], 1)
        self.assertEqual(summary["statistics"]["directory_scan_completed_count"], 1)
        self.assertEqual(summary["statistics"]["total_web_targets"], 2)
        self.assertEqual(summary["statistics"]["total_dirsearch_findings"], 3)

    def test_run_forwards_scan_options_to_scanner(self):
        class FakeScanner:
            def __init__(self):
                self.calls = []

            def scan(self, **kwargs):
                self.calls.append(kwargs)
                return {
                    "subdomains": [{"subdomain": "www.example.com", "ip": ["1.1.1.1"]}],
                    "wildcard": {"detected": False},
                    "statistics": {"total_found": 1},
                    "tool_runs": {},
                }

            def save_result(self):
                return None

        scanner = FakeScanner()
        runner = BatchScanRunner(
            scanner=scanner,
            run_port_scan=lambda *args, **kwargs: {},
            run_web_fingerprint=lambda *args, **kwargs: {},
            run_directory_scan=lambda *args, **kwargs: {},
        )

        runner.run(
            domains=["example.com"],
            tools=["subfinder"],
            skip_wildcard=True,
            skip_validation=True,
            parallel=False,
        )

        self.assertEqual(len(scanner.calls), 1)
        self.assertTrue(scanner.calls[0]["skip_wildcard"])
        self.assertTrue(scanner.calls[0]["skip_validation"])
        self.assertFalse(scanner.calls[0]["parallel"])


if __name__ == "__main__":
    unittest.main()
