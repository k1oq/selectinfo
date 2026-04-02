import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config
import scan


class ScanEntrypointTests(unittest.TestCase):
    def test_parse_cli_tool_overrides_parses_and_ignores_blank_values(self):
        args = Namespace(
            subfinder_args="",
            oneforall_args="   ",
            nmap_args='-sV -Pn --script "banner"',
            dirsearch_args=None,
        )

        raw_overrides, runtime_overrides = scan.parse_cli_tool_overrides(args)

        self.assertEqual(raw_overrides, {"nmap": '-sV -Pn --script "banner"'})
        self.assertEqual(
            runtime_overrides,
            {"nmap": {"args": config.parse_cli_args('-sV -Pn --script "banner"')}},
        )

    def test_parse_cli_tool_overrides_rejects_reserved_tokens(self):
        args = Namespace(
            subfinder_args=None,
            oneforall_args=None,
            nmap_args="-p 80",
            dirsearch_args=None,
        )

        with self.assertRaises(ValueError):
            scan.parse_cli_tool_overrides(args)

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
            background=False,
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
            background=False,
        )

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan.NmapSetupManager, "is_available", return_value=True
        ), mock.patch.object(
            scan, "run_single_scan", return_value={"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}
        ) as run_single_scan:
            result = scan.execute(args)

        self.assertEqual(result["saved_path"], Path("result.json"))
        run_single_scan.assert_called_once()
        call_kwargs = run_single_scan.call_args.kwargs
        self.assertEqual(call_kwargs["tools"], ["subfinder"])
        self.assertTrue(call_kwargs["enable_port_scan"])
        self.assertTrue(call_kwargs["enable_web_fingerprint"])

    def test_execute_preset_applies_runtime_overrides_without_enabling_stages(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": True,
            "oneforall": True,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools=None,
            preset="quick",
            subfinder_args=None,
            oneforall_args=None,
            nmap_args=None,
            dirsearch_args=None,
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        def run_single_scan_side_effect(*_args, **kwargs):
            self.assertEqual(config.get_tool_settings("subfinder")["timeout"], 300)
            self.assertEqual(config.get_tool_settings("oneforall")["timeout"], 600)
            return {"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan, "run_single_scan", side_effect=run_single_scan_side_effect
        ) as run_single_scan:
            scan.execute(args)

        call_kwargs = run_single_scan.call_args.kwargs
        self.assertEqual(call_kwargs["scan_preset"], "quick")
        self.assertEqual(call_kwargs["tools"], ["subfinder", "oneforall"])
        self.assertFalse(call_kwargs["enable_port_scan"])
        self.assertFalse(call_kwargs["enable_web_fingerprint"])
        self.assertFalse(call_kwargs["enable_directory_scan"])

    def test_execute_nmap_args_auto_enable_port_scan_and_apply_runtime_override(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": True,
            "oneforall": False,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools="subfinder",
            subfinder_args=None,
            oneforall_args=None,
            nmap_args="-sV -Pn",
            dirsearch_args=None,
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        def run_single_scan_side_effect(*_args, **kwargs):
            self.assertEqual(config.get_tool_settings("nmap")["args"], ["-sV", "-Pn"])
            return {"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}

        original_local_settings = config.load_local_settings()

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan.NmapSetupManager, "is_available", return_value=True
        ), mock.patch.object(
            scan, "run_single_scan", side_effect=run_single_scan_side_effect
        ) as run_single_scan:
            result = scan.execute(args)

        self.assertEqual(result["saved_path"], Path("result.json"))
        self.assertTrue(run_single_scan.call_args.kwargs["enable_port_scan"])
        self.assertEqual(config.load_local_settings(), original_local_settings)

    def test_execute_cli_tool_override_wins_over_preset(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": True,
            "oneforall": False,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools="subfinder",
            preset="quick",
            subfinder_args=None,
            oneforall_args=None,
            nmap_args="-sV -Pn",
            dirsearch_args=None,
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        def run_single_scan_side_effect(*_args, **kwargs):
            self.assertEqual(config.get_tool_settings("nmap")["timeout"], 300)
            self.assertEqual(config.get_tool_settings("nmap")["args"], ["-sV", "-Pn"])
            return {"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan.NmapSetupManager, "is_available", return_value=True
        ), mock.patch.object(
            scan, "run_single_scan", side_effect=run_single_scan_side_effect
        ) as run_single_scan:
            scan.execute(args)

        self.assertEqual(run_single_scan.call_args.kwargs["scan_preset"], "quick")

    def test_execute_quick_preset_falls_back_to_available_tool(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": False,
            "oneforall": True,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools=None,
            preset="quick",
            subfinder_args=None,
            oneforall_args=None,
            nmap_args=None,
            dirsearch_args=None,
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan, "run_single_scan", return_value={"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}
        ) as run_single_scan:
            scan.execute(args)

        self.assertEqual(run_single_scan.call_args.kwargs["tools"], ["oneforall"])

    def test_execute_dirsearch_args_auto_enable_followup_stages(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": True,
            "oneforall": False,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools="subfinder",
            subfinder_args=None,
            oneforall_args=None,
            nmap_args=None,
            dirsearch_args="--exclude-status 403",
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan.NmapSetupManager, "is_available", return_value=True
        ), mock.patch.object(
            scan.DirsearchTool, "check_json_support", return_value={"usable": True}
        ), mock.patch.object(
            scan, "run_single_scan", return_value={"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}
        ) as run_single_scan:
            scan.execute(args)

        call_kwargs = run_single_scan.call_args.kwargs
        self.assertTrue(call_kwargs["enable_port_scan"])
        self.assertTrue(call_kwargs["enable_web_fingerprint"])
        self.assertTrue(call_kwargs["enable_directory_scan"])

    def test_execute_subfinder_args_select_only_subfinder_when_tools_not_given(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": True,
            "oneforall": True,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools=None,
            subfinder_args="-rl 50",
            oneforall_args=None,
            nmap_args=None,
            dirsearch_args=None,
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan, "run_single_scan", return_value={"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}
        ) as run_single_scan:
            scan.execute(args)

        self.assertEqual(run_single_scan.call_args.kwargs["tools"], ["subfinder"])

    def test_execute_tool_args_are_merged_with_requested_tools(self):
        fake_scanner = mock.Mock()
        fake_scanner.AVAILABLE_TOOLS = {"subfinder": object(), "oneforall": object()}
        fake_scanner.check_tools.return_value = {
            "subfinder": True,
            "oneforall": True,
        }

        args = Namespace(
            target="example.com",
            targets_file=None,
            tools="oneforall",
            subfinder_args="-rl 50",
            oneforall_args=None,
            nmap_args=None,
            dirsearch_args=None,
            skip_wildcard=False,
            skip_validation=False,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=False,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        with mock.patch.object(scan, "SubdomainScanner", return_value=fake_scanner), mock.patch.object(
            scan, "print_plan"
        ), mock.patch.object(
            scan, "run_single_scan", return_value={"saved_path": Path("result.json"), "report_path": Path("result.summary.xlsx")}
        ) as run_single_scan:
            scan.execute(args)

        self.assertEqual(run_single_scan.call_args.kwargs["tools"], ["oneforall", "subfinder"])

    def test_validate_followup_tools_checks_nmap_separately(self):
        with mock.patch.object(scan.NmapSetupManager, "is_available", return_value=False):
            with self.assertRaises(ValueError):
                scan.validate_followup_tools(
                    {},
                    enable_port_scan=True,
                    enable_web_fingerprint=False,
                    enable_directory_scan=False,
                )

    def test_validate_followup_tools_warns_when_dirsearch_unavailable(self):
        with mock.patch.object(
            scan.DirsearchTool,
            "check_json_support",
            return_value={"usable": False},
        ), mock.patch.object(scan.console, "print") as console_print:
            scan.validate_followup_tools(
                {"subfinder": True},
                enable_port_scan=False,
                enable_web_fingerprint=False,
                enable_directory_scan=True,
            )

        console_print.assert_called_once()

    def test_execute_rejects_directory_scan_without_validation(self):
        args = Namespace(
            target="example.com",
            targets_file=None,
            tools="subfinder",
            skip_wildcard=False,
            skip_validation=True,
            serial=False,
            port_scan=False,
            port_mode="common",
            web_fingerprint=False,
            directory_scan=True,
            results_dir=None,
            output=None,
            summary_output=None,
            background=False,
        )

        with self.assertRaises(ValueError):
            scan.execute(args)

    def test_launch_background_scan_wraps_current_command(self):
        with mock.patch.object(scan, "create_background_job", return_value={
            "job_id": "scan_123",
            "job_dir": Path("runtime/jobs/scan_123"),
            "status_path": Path("runtime/jobs/scan_123/status.json"),
            "log_path": Path("runtime/jobs/scan_123/scan.log"),
            "command_path": Path("runtime/jobs/scan_123/command.txt"),
        }), mock.patch.object(scan, "launch_background_command", return_value={
            "job_id": "scan_123",
            "pid": 4321,
            "status_path": Path("runtime/jobs/scan_123/status.json"),
            "log_path": Path("runtime/jobs/scan_123/scan.log"),
        }) as launch:
            result = scan.launch_background_scan(["example.com", "--background", "--port-scan"])

        self.assertEqual(result["job_id"], "scan_123")
        launch.assert_called_once()
        command = launch.call_args.args[0]
        self.assertNotIn("--background", command)
        self.assertIn("--_background-child", command)
        self.assertIn("example.com", command)
        self.assertIn("--port-scan", command)

    def test_run_single_scan_sets_scan_preset_on_result(self):
        class FakeScanner:
            def __init__(self):
                self.last_result = None

            def scan(self, **kwargs):
                self.last_result = {
                    "wildcard": {"detected": False},
                    "subdomains": [],
                }
                return self.last_result

            def save_result(self, output_path=None):
                destination = Path(output_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("{}", encoding="utf-8")
                return destination

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "example.json"
            scanner = FakeScanner()
            scan.run_single_scan(
                scanner,
                target="example.com",
                tools=["subfinder"],
                scan_preset="deep",
                skip_wildcard=False,
                skip_validation=False,
                parallel=True,
                enable_port_scan=False,
                port_mode="common",
                enable_web_fingerprint=False,
                enable_directory_scan=False,
                output_path=str(output_path),
            )

        self.assertEqual(scanner.last_result["scan_preset"], "deep")

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
            report_path = Path(tmp) / "example.summary.xlsx"

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
            scan, "write_batch_item_reports", return_value=[Path("a.summary.xlsx")]
        ) as write_item_reports, mock.patch.object(
            scan, "write_batch_summary_report", return_value=Path("batch.summary.xlsx")
        ) as write_summary_report:
            batch_runner = batch_runner_cls.return_value
            batch_runner.run.return_value = (fake_batch_summary, fake_summary_path)

            result = scan.run_batch_scan(
                mock.Mock(),
                targets=["example.com"],
                tools=["subfinder"],
                scan_preset="quick",
                skip_wildcard=False,
                skip_validation=False,
                parallel=True,
                enable_port_scan=False,
                port_mode="common",
                enable_web_fingerprint=False,
                enable_directory_scan=False,
                summary_output="batch.summary.xlsx",
            )

        self.assertEqual(result["summary_path"], fake_summary_path)
        self.assertEqual(result["report_path"], Path("batch.summary.xlsx"))
        self.assertEqual(batch_runner.run.call_args.kwargs["scan_preset"], "quick")
        write_item_reports.assert_called_once_with(fake_batch_summary)
        write_summary_report.assert_called_once_with(
            fake_batch_summary,
            fake_summary_path,
            output_path="batch.summary.xlsx",
        )


if __name__ == "__main__":
    unittest.main()
