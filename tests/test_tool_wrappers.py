import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config
from tools.dirsearch_wrapper import DirsearchTool
from tools.oneforall_wrapper import OneForAllTool
from tools.subfinder_wrapper import SubfinderTool


class ToolWrapperFallbackTests(unittest.TestCase):
    def setUp(self):
        self._original_settings = config.load_local_settings()

    def tearDown(self):
        config.save_local_settings(self._original_settings)

    def test_subfinder_falls_back_to_default_when_configured_path_is_missing(self):
        config.set_tool_path("subfinder", "C:/missing/subfinder.exe")
        tool = SubfinderTool()
        self.assertEqual(tool.executable, tool.default_executable)
        self.assertTrue(tool.is_installed())

    def test_oneforall_falls_back_to_default_when_configured_path_is_missing(self):
        config.set_tool_path("oneforall", "C:/missing/oneforall.py")
        tool = OneForAllTool()
        self.assertEqual(tool.tool_dir, tool.default_tool_dir)
        self.assertEqual(tool.script_path, tool.default_tool_dir / "oneforall.py")
        self.assertTrue(tool.is_installed())

    def test_dirsearch_falls_back_to_default_when_configured_path_is_missing(self):
        config.set_tool_path("dirsearch", "C:/missing/dirsearch.py")
        tool = DirsearchTool()
        self.assertEqual(tool.executable, tool.default_executable)
        self.assertTrue(tool.is_installed())


class SubfinderToolTests(unittest.TestCase):
    def test_scan_marks_nonzero_returncode_as_error(self):
        tool = SubfinderTool()
        tool.executable = Path("subfinder")

        with mock.patch.object(tool, "is_installed", return_value=True), mock.patch(
            "tools.subfinder_wrapper.subprocess.run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="permission denied"),
        ):
            result = tool.scan("example.com")

        self.assertEqual(result, [])
        self.assertEqual(tool.get_last_run()["status"], "error")
        self.assertEqual(tool.get_last_run()["return_code"], 1)
        self.assertIn("执行失败", tool.get_last_run()["message"])

    def test_scan_uses_strict_domain_filtering(self):
        tool = SubfinderTool()
        tool.executable = Path("subfinder")

        completed = mock.Mock(
            returncode=0,
            stdout="\n".join(
                [
                    "www.example.com",
                    "fooexample.com",
                    "EXAMPLE.com",
                    "api.example.com.",
                ]
            ),
            stderr="",
        )
        with mock.patch.object(tool, "is_installed", return_value=True), mock.patch(
            "tools.subfinder_wrapper.subprocess.run",
            return_value=completed,
        ):
            result = tool.scan("example.com")

        self.assertEqual(result, ["api.example.com", "example.com", "www.example.com"])
        self.assertEqual(tool.get_last_run()["status"], "completed")
        self.assertEqual(tool.get_last_run()["raw_count"], 4)
        self.assertEqual(tool.get_last_run()["valid_count"], 3)


class OneForAllToolTests(unittest.TestCase):
    def _build_fake_tool(self, temp_dir: Path) -> OneForAllTool:
        tool = OneForAllTool()
        tool.tool_dir = temp_dir
        tool.script_path = temp_dir / "oneforall.py"
        tool.script_path.write_text("print('ok')", encoding="utf-8")
        tool.results_dir = temp_dir / "results"
        tool.results_dir.mkdir(parents=True, exist_ok=True)
        return tool

    def test_nonzero_returncode_does_not_reuse_stale_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_dir = Path(tmp)
            tool = self._build_fake_tool(temp_dir)
            stale_file = tool.results_dir / "example.com.csv"
            stale_file.write_text("subdomain\nold.example.com\n", encoding="utf-8")
            output_path = temp_dir / "fresh.csv"

            with mock.patch.object(tool, "is_installed", return_value=True), mock.patch.object(
                tool, "_build_output_path", return_value=output_path
            ), mock.patch(
                "tools.oneforall_wrapper.subprocess.run",
                return_value=mock.Mock(returncode=1, stdout="", stderr="boom"),
            ):
                result = tool.scan("example.com")

        self.assertEqual(result, [])
        self.assertEqual(tool.get_last_run()["status"], "error")
        self.assertEqual(tool.get_last_run()["return_code"], 1)

    def test_scan_parses_only_the_unique_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_dir = Path(tmp)
            tool = self._build_fake_tool(temp_dir)
            output_path = temp_dir / "unique.csv"
            with open(output_path, "w", encoding="utf-8", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=["subdomain"])
                writer.writeheader()
                writer.writerow({"subdomain": "www.example.com"})
                writer.writerow({"subdomain": "fooexample.com"})
                writer.writerow({"subdomain": "https://api.example.com"})

            with mock.patch.object(tool, "is_installed", return_value=True), mock.patch.object(
                tool, "_build_output_path", return_value=output_path
            ), mock.patch(
                "tools.oneforall_wrapper.subprocess.run",
                return_value=mock.Mock(returncode=0, stdout="ok", stderr=""),
            ) as run_mock:
                result = tool.scan("example.com")

        self.assertEqual(result, ["api.example.com", "www.example.com"])
        self.assertEqual(tool.get_last_run()["status"], "completed")
        self.assertEqual(tool.get_last_run()["raw_count"], 3)
        self.assertEqual(tool.get_last_run()["valid_count"], 2)
        self.assertIn("--path", run_mock.call_args.args[0])
        self.assertIn(str(output_path), run_mock.call_args.args[0])

    def test_domain_registered_handles_missing_use_tld_extract_flag(self):
        script = (
            "from config import settings\n"
            "from common import utils\n"
            "if hasattr(settings, 'use_tld_extract'):\n"
            "    delattr(settings, 'use_tld_extract')\n"
            "print(utils.get_main_domain('www.example.com'))\n"
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(Path(PROJECT_ROOT) / "tools" / "oneforall"),
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        self.assertEqual(result.stdout.strip(), "example.com")

    def test_domain_registered_falls_back_to_matched_host_when_extract_is_empty(self):
        script = (
            "from common import utils\n"
            "from common.domain import Domain\n"
            "Domain.extract = lambda self: type('Result', (), {'registered_domain': ''})()\n"
            "print(utils.get_main_domain('landui.com'))\n"
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(Path(PROJECT_ROOT) / "tools" / "oneforall"),
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        self.assertEqual(result.stdout.strip(), "landui.com")

    def test_scan_marks_empty_export_with_actionable_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_dir = Path(tmp)
            tool = self._build_fake_tool(temp_dir)
            output_path = temp_dir / "empty.csv"
            output_path.write_text("id,subdomain\n", encoding="utf-8")

            with mock.patch.object(tool, "is_installed", return_value=True), mock.patch.object(
                tool, "_build_output_path", return_value=output_path
            ), mock.patch(
                "tools.oneforall_wrapper.subprocess.run",
                return_value=mock.Mock(returncode=0, stdout="ok", stderr=""),
            ):
                result = tool.scan("example.com")

        self.assertEqual(result, [])
        self.assertEqual(tool.get_last_run()["status"], "completed")
        self.assertEqual(tool.get_last_run()["raw_count"], 0)
        self.assertIn("未导出任何结果", tool.get_last_run()["message"])


if __name__ == "__main__":
    unittest.main()
