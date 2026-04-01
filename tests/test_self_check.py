import unittest
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
from tools.self_check import ToolSelfChecker


class ToolSelfCheckerTests(unittest.TestCase):
    def test_check_oneforall_reports_sqlite_probe_failure(self):
        checker = ToolSelfChecker()

        with mock.patch.object(checker.oneforall, "is_installed", return_value=True), mock.patch.object(
            ToolSelfChecker,
            "_run_command",
            return_value={
                "ok": False,
                "stdout": "",
                "stderr": "ModuleNotFoundError: No module named '_sqlite3'",
                "message": "执行失败: ModuleNotFoundError: No module named '_sqlite3'",
            },
        ):
            result = checker.check_oneforall()

        self.assertTrue(result.installed)
        self.assertFalse(result.usable)
        self.assertIn("sqlite3", result.message)
        self.assertIn("fallback", result.message)

    def test_check_oneforall_probes_sqlite_before_help(self):
        checker = ToolSelfChecker()

        with mock.patch.object(checker.oneforall, "is_installed", return_value=True), mock.patch.object(
            checker.oneforall, "get_version", return_value="v0.4.5"
        ), mock.patch.object(
            ToolSelfChecker,
            "_run_command",
            side_effect=[
                {
                    "ok": True,
                    "stdout": "pysqlite3:3.51.1\n",
                    "stderr": "",
                    "message": "ok",
                },
                {
                    "ok": True,
                    "stdout": "usage: oneforall.py\n",
                    "stderr": "",
                    "message": "ok",
                },
            ],
        ) as run_command:
            result = checker.check_oneforall()

        self.assertTrue(result.usable)
        self.assertEqual(result.version, "v0.4.5")
        self.assertIn("sqlite", result.message)
        first_call = run_command.call_args_list[0]
        self.assertEqual(
            first_call.args[0],
            ToolSelfChecker._build_oneforall_sqlite_probe_command(),
        )

    def test_run_command_permission_error_contains_actionable_hint(self):
        with mock.patch("tools.self_check.sys.platform", "linux"), mock.patch(
            "tools.self_check.subprocess.run",
            side_effect=PermissionError("[Errno 13] Permission denied"),
        ):
            result = ToolSelfChecker._run_command(["/tmp/subfinder"], timeout=5)

        self.assertFalse(result["ok"])
        self.assertIn("chmod +x", result["message"])


if __name__ == "__main__":
    unittest.main()
