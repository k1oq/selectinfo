import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
from tools.self_check import ToolSelfChecker


class ToolSelfCheckerTests(unittest.TestCase):
    def test_check_oneforall_reports_sqlite_probe_failure(self):
        checker = ToolSelfChecker()

        with mock.patch.object(checker.oneforall, "is_installed", return_value=True), mock.patch.object(
            ToolSelfChecker,
            "_probe_oneforall_sqlite",
            return_value={
                "ok": False,
                "stdout": "",
                "stderr": "ModuleNotFoundError: No module named '_sqlite3'",
                "message": "Python sqlite3 不可用: 执行失败: ModuleNotFoundError: No module named '_sqlite3'",
            },
        ):
            result = checker.check_oneforall()

        self.assertTrue(result.installed)
        self.assertFalse(result.usable)
        self.assertIn("sqlite3", result.message)

    def test_check_oneforall_probes_sqlite_before_help(self):
        checker = ToolSelfChecker()

        with mock.patch.object(checker.oneforall, "is_installed", return_value=True), mock.patch.object(
            checker.oneforall, "get_version", return_value="v0.4.5"
        ), mock.patch.object(
            ToolSelfChecker,
            "_probe_oneforall_sqlite",
            return_value={
                "ok": True,
                "stdout": "stdlib:3.51.1\n",
                "stderr": "",
                "message": "ok",
            },
        ), mock.patch.object(
            ToolSelfChecker,
            "_run_command",
            return_value={
                "ok": True,
                "stdout": "usage: oneforall.py\n",
                "stderr": "",
                "message": "ok",
            },
        ) as run_command:
            result = checker.check_oneforall()

        self.assertTrue(result.usable)
        self.assertEqual(result.version, "v0.4.5")
        self.assertIn("sqlite", result.message)
        self.assertEqual(run_command.call_count, 1)

    def test_probe_oneforall_sqlite_prefers_stdlib(self):
        with TemporaryDirectory() as temp_dir, mock.patch.object(
            ToolSelfChecker,
            "_run_command",
            return_value={
                "ok": True,
                "stdout": "stdlib:3.51.1\n",
                "stderr": "",
                "message": "ok",
            },
        ) as run_command:
            result = ToolSelfChecker._probe_oneforall_sqlite(Path(temp_dir))

        self.assertTrue(result["ok"])
        self.assertEqual(run_command.call_count, 1)
        self.assertEqual(run_command.call_args_list[0].args[0], ToolSelfChecker._build_sqlite_probe_command())

    def test_probe_oneforall_sqlite_uses_fallback_when_helper_exists(self):
        with TemporaryDirectory() as temp_dir:
            compat_file = Path(temp_dir) / "sqlite_compat.py"
            compat_file.write_text("def ensure_sqlite3():\n    return 'pysqlite3'\n", encoding="utf-8")

            with mock.patch.object(
                ToolSelfChecker,
                "_run_command",
                side_effect=[
                    {
                        "ok": False,
                        "stdout": "",
                        "stderr": "ModuleNotFoundError",
                        "message": "执行失败: ModuleNotFoundError",
                    },
                    {
                        "ok": True,
                        "stdout": "pysqlite3:3.51.1\n",
                        "stderr": "",
                        "message": "ok",
                    },
                ],
            ) as run_command:
                result = ToolSelfChecker._probe_oneforall_sqlite(Path(temp_dir))

        self.assertTrue(result["ok"])
        self.assertEqual(run_command.call_count, 2)
        self.assertEqual(run_command.call_args_list[0].args[0], ToolSelfChecker._build_sqlite_probe_command())
        self.assertEqual(run_command.call_args_list[1].args[0], ToolSelfChecker._build_oneforall_sqlite_probe_command())

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
