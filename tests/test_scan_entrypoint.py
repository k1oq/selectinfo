import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
import scan


class ScanEntrypointTests(unittest.TestCase):
    def test_resolve_stage_flags_auto_enables_dependencies(self):
        self.assertEqual(
            scan.resolve_stage_flags(False, False, True),
            (True, True, True),
        )
        self.assertEqual(
            scan.resolve_stage_flags(False, True, False),
            (True, True, False),
        )

    def test_execute_rejects_output_path_in_batch_mode(self):
        args = Namespace(
            target=None,
            targets_file="domains.txt",
            tools=None,
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output="out.json",
            summary_output=None,
        )

        with mock.patch.object(scan, "resolve_targets", return_value=["a.com", "b.com"]):
            with self.assertRaises(ValueError):
                scan.execute(args)

    def test_execute_single_target_dispatches_to_run_single_scan(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": True,
            "oneforall": False,
            "nmap": True,
            "dirsearch": True,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools="subfinder",
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=True,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
        )

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan, "run_single_scan", return_value={"saved_path": Path("result.json"), "report_path": Path("result.summary.csv")}
        ) as run_single_scan:
            result = scan.execute(args)

        self.assertEqual(result["saved_path"], Path("result.json"))
        run_single_scan.assert_called_once()
        call_kwargs = run_single_scan.call_args.kwargs
        self.assertEqual(call_kwargs["tools"], ["subfinder"])
        self.assertTrue(call_kwargs["enable_port_scan"])
        self.assertTrue(call_kwargs["enable_web_fingerprint"])

    def test_run_single_scan_writes_summary_after_followups(self):
        class FakeScanner:
            def scan(self, **kwargs):
                return {
                    "wildcard": {"detected": False},
                    "subdomains": [{"subdomain": "www.example.com", "ip": ["1.1.1.1"]}],
                }

            def save_result(self, output_path=None):
                destination = Path(output_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("{}", encoding="utf-8")
                return destination

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "example.json"
            report_path = Path(tmp) / "example.summary.csv"

            with mock.patch.object(scan, "run_port_scan", return_value={"1.1.1.1": [80]}), mock.patch.object(
                scan, "run_web_fingerprint", return_value={"targets": [{"url": "http://www.example.com"}]}
            ), mock.patch.object(
                scan, "run_directory_scan", return_value={"statistics": {"interesting_path_count": 1}}
            ) as run_directory_scan, mock.patch.object(
                scan, "write_single_scan_report_from_file", return_value=report_path
            ) as write_report:
                result = scan.run_single_scan(
                    FakeScanner(),
                    target="example.com",
                    tools=["subfinder"],
                    skip_wildcard=False,
                    skip_validation=False,
                    parallel=True,
                    enable_port_scan=True,
                    port_mode="common",
                    enable_web_fingerprint=True,
                    enable_directory_scan=True,
                    output_path=str(output_path),
                    summary_output=str(report_path),
                )

        self.assertEqual(result["saved_path"], output_path)
        self.assertEqual(result["report_path"], report_path)
        self.assertTrue(run_directory_scan.called)
        write_report.assert_called_once_with(output_path, output_path=str(report_path))

    def test_run_batch_scan_writes_reports(self):
        fake_batch_summary = {
            "statistics": {"success_count": 1, "total_domains": 1},
            "items": [{"saved_path": str(Path(PROJECT_ROOT) / "results" / "a.json")}],
        }
        fake_summary_path = Path(PROJECT_ROOT) / "results" / "batch_summary.json"

        with mock.patch.object(scan, "BatchScanRunner") as batch_runner_cls, mock.patch.object(
            scan, "write_batch_item_reports", return_value=[Path("a.summary.csv")]
        ) as write_item_reports, mock.patch.object(
            scan, "write_batch_summary_report", return_value=Path("batch.summary.csv")
        ) as write_summary_report:
            batch_runner = batch_runner_cls.return_value
            batch_runner.run.return_value = (fake_batch_summary, fake_summary_path)

            result = scan.run_batch_scan(
                mock.Mock(),
                targets=["example.com"],
                tools=["subfinder"],
                skip_wildcard=False,
                skip_validation=False,
                parallel=True,
                enable_port_scan=False,
                port_mode="common",
                enable_web_fingerprint=False,
                enable_directory_scan=False,
                summary_output="batch.summary.csv",
            )

        self.assertEqual(result["summary_path"], fake_summary_path)
        self.assertEqual(result["report_path"], Path("batch.summary.csv"))
        write_item_reports.assert_called_once_with(fake_batch_summary)
        write_summary_report.assert_called_once_with(
            fake_batch_summary,
            fake_summary_path,
            output_path="batch.summary.csv",
        )


if __name__ == "__main__":
    unittest.main()
