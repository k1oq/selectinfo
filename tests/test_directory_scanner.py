import tempfile
import unittest
from pathlib import Path

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config
from core.directory_scanner import DirectoryScanner
from tools.dirsearch_wrapper import DirsearchTool


class FakeDirsearchUnavailable:
    def check_json_support(self):
        return {"usable": False}


class FakeDirsearchAvailable:
    def check_json_support(self):
        return {"usable": True}

    def scan_url(self, url):
        return {
            "status": "completed",
            "command": f"dirsearch -u {url}",
            "findings": [{"path": "/admin", "status": 200, "size": 123, "redirect": ""}],
        }


class DirectoryScannerTests(unittest.TestCase):
    def test_scan_marks_targets_skipped_when_dirsearch_unavailable(self):
        scanner = DirectoryScanner(dirsearch_tool=FakeDirsearchUnavailable())
        result = scanner.scan(
            [{"subdomain": "www.example.com", "ip": "1.1.1.1", "port": 80, "scheme": "http", "url": "http://www.example.com"}]
        )

        self.assertEqual(result["statistics"]["target_count"], 1)
        self.assertEqual(result["statistics"]["skipped_unavailable_count"], 1)
        self.assertEqual(result["targets"][0]["status"], "skipped_unavailable")

    def test_scan_runs_dirsearch_for_identified_web_targets(self):
        scanner = DirectoryScanner(dirsearch_tool=FakeDirsearchAvailable())
        result = scanner.scan(
            [{"subdomain": "www.example.com", "ip": "1.1.1.1", "port": 80, "scheme": "http", "url": "http://www.example.com"}]
        )

        self.assertEqual(result["statistics"]["completed_count"], 1)
        self.assertEqual(result["statistics"]["interesting_path_count"], 1)
        self.assertEqual(result["targets"][0]["findings"][0]["path"], "/admin")


class DirsearchToolTests(unittest.TestCase):
    def setUp(self):
        self._original_settings = config.load_local_settings()

    def tearDown(self):
        config.save_local_settings(self._original_settings)

    def test_build_scan_command_includes_default_stealth_args(self):
        tool = DirsearchTool()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as file:
            output_path = Path(file.name)

        try:
            command, _ = tool.build_scan_command("http://example.com", output_path)
        finally:
            output_path.unlink(missing_ok=True)

        self.assertIn("--random-agent", command)
        self.assertIn("--delay", command)
        self.assertIn("0.2", command)
        self.assertIn("--max-rate", command)
        self.assertIn("3", command)
        self.assertIn("--retries", command)
        self.assertIn("1", command)
        self.assertIn("--exclude-status", command)
        self.assertIn("404,429,500-999", command)

    def test_user_args_override_default_stealth_flags(self):
        config.set_tool_settings(
            "dirsearch",
            {
                "extra_args": config.parse_cli_args("--exclude-status 403 --delay 1.0 --random-agent"),
            },
        )
        tool = DirsearchTool()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as file:
            output_path = Path(file.name)

        try:
            command, _ = tool.build_scan_command("http://example.com", output_path)
        finally:
            output_path.unlink(missing_ok=True)

        self.assertEqual(command.count("--exclude-status"), 1)
        self.assertIn("403", command)
        self.assertEqual(command.count("--delay"), 1)
        self.assertIn("1.0", command)
        self.assertEqual(command.count("--random-agent"), 1)

    def test_stringify_command_supports_posix_style_output(self):
        command_text = DirsearchTool._stringify_command(
            ["python3", "dirsearch.py", "-u", "http://example.com/has space"],
            prefer_posix=True,
        )

        self.assertEqual(
            command_text,
            "python3 dirsearch.py -u 'http://example.com/has space'",
        )

    def test_stringify_command_supports_windows_style_output(self):
        command_text = DirsearchTool._stringify_command(
            ["python", "dirsearch.py", "-u", "http://example.com/has space"],
            prefer_posix=False,
        )

        self.assertEqual(
            command_text,
            'python dirsearch.py -u "http://example.com/has space"',
        )


if __name__ == "__main__":
    unittest.main()
