import tempfile
import unittest
from io import StringIO
from pathlib import Path
import csv

from _bootstrap import PROJECT_ROOT  # noqa: F401
from core.human_reports import (
    build_batch_summary_report,
    build_single_scan_report,
    default_report_path,
    write_csv_report,
)


class HumanReportsTests(unittest.TestCase):
    def test_single_scan_report_contains_key_sections(self):
        report = build_single_scan_report(
            {
                "target": "example.com",
                "scan_time": "2026-04-01T10:00:00",
                "duration_seconds": 12.5,
                "tools_used": ["subfinder", "oneforall"],
                "wildcard": {"detected": False},
                "statistics": {"total_found": 5, "valid_count": 3, "filtered_count": 2},
                "tool_runs": {
                    "subfinder": {
                        "status": "completed",
                        "return_code": 0,
                        "message": "ok",
                        "raw_count": 5,
                        "valid_count": 3,
                    }
                },
                "subdomains": [{"subdomain": "www.example.com", "ip": ["1.1.1.1"]}],
                "port_scan": {
                    "statistics": {"total_open_ports": 2},
                    "hosts": {"1.1.1.1": [80, 443]},
                },
                "web_fingerprint": {
                    "statistics": {"web_target_count": 1},
                    "targets": [
                        {
                            "url": "https://www.example.com",
                            "ip": "1.1.1.1",
                            "nmap": {"title": "Example"},
                        }
                    ],
                },
                "directory_scan": {
                    "statistics": {"interesting_path_count": 1},
                    "targets": [
                        {
                            "url": "https://www.example.com",
                            "findings": [{"path": "/admin", "status": 200, "redirect": ""}],
                        }
                    ],
                },
            },
            source_path=Path(PROJECT_ROOT) / "results" / "example.json",
        )

        rows = list(csv.DictReader(StringIO(report)))
        self.assertEqual(rows[0]["分组"], "概览")
        self.assertEqual(rows[0]["名称"], "目标域名")
        self.assertEqual(rows[0]["数值"], "example.com")
        self.assertTrue(any(row["分组"] == "工具状态" and row["名称"] == "subfinder" for row in rows))
        self.assertTrue(any(row["分组"] == "Web目标" and row["名称"] == "https://www.example.com" for row in rows))
        self.assertTrue(any(row["分组"] == "目录发现" and row["数值"] == "/admin" for row in rows))

    def test_batch_summary_report_contains_overview_and_failures(self):
        report = build_batch_summary_report(
            {
                "scan_time": "2026-04-01T10:00:00",
                "tools_used": ["subfinder"],
                "statistics": {
                    "requested_domains": 2,
                    "total_domains": 2,
                    "success_count": 1,
                    "error_count": 1,
                    "no_valid_result_count": 0,
                    "total_open_ports": 4,
                    "total_web_targets": 2,
                    "total_dirsearch_findings": 1,
                },
                "items": [
                    {
                        "domain": "a.com",
                        "status": "success",
                        "valid_count": 2,
                        "open_port_count": 4,
                        "web_target_count": 2,
                        "dirsearch_finding_count": 1,
                        "message": "ok",
                    },
                    {
                        "domain": "b.com",
                        "status": "error",
                        "valid_count": 0,
                        "open_port_count": 0,
                        "web_target_count": 0,
                        "dirsearch_finding_count": 0,
                        "message": "boom",
                    },
                ],
            },
            source_path=Path(PROJECT_ROOT) / "results" / "batch_summary.json",
        )

        rows = list(csv.DictReader(StringIO(report)))
        self.assertTrue(any(row["分组"] == "统计" and row["名称"] == "成功数" and row["数值"] == "1" for row in rows))
        self.assertTrue(any(row["分组"] == "域名概览" and row["名称"] == "a.com" for row in rows))
        self.assertTrue(any(row["分组"] == "域名概览" and row["名称"] == "b.com" and row["状态"] == "error" for row in rows))

    def test_write_csv_report_uses_target_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "example.summary.csv"
            written = write_csv_report("序号,分组\n1,概览\n", output_path)

            self.assertEqual(written, output_path)
            self.assertIn("序号,分组", output_path.read_text(encoding="utf-8-sig"))
            self.assertEqual(default_report_path(Path(tmp) / "a.json"), Path(tmp) / "a.summary.csv")


if __name__ == "__main__":
    unittest.main()
