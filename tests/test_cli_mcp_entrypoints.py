import json
import subprocess
import sys
import unittest
from pathlib import Path

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config


class CliAndMcpEntrypointsTests(unittest.TestCase):
    def setUp(self):
        self.project_root = Path(PROJECT_ROOT)
        self._original_settings = config.load_local_settings()

    def tearDown(self):
        config.save_local_settings(self._original_settings)

    def _run(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *args],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _run_json(self, *args) -> dict:
        result = self._run(*args)
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        return json.loads(result.stdout)

    def test_root_cli_show_outputs_config(self):
        result = self._run_json("cli.py", "-show")
        self.assertTrue(result["ok"])
        self.assertIn("show", result)
        self.assertIn("tools", result["show"])

    def test_root_cli_check_outputs_self_check(self):
        result = self._run_json("cli.py", "-check")
        self.assertTrue(result["ok"])
        self.assertIn("self_check", result)
        self.assertIn("nmap", result["self_check"])

    def test_root_cli_updates_nmap_args(self):
        result = self._run_json("cli.py", "-nmap", "-sS -Pn")
        action = result["actions"][0]["result"]
        self.assertEqual(action["effective_settings"]["args"], ["-sS", "-Pn"])

    def test_root_cli_updates_oneforall_extra_args(self):
        result = self._run_json("cli.py", "-oneforall", "--takeover False")
        action = result["actions"][0]["result"]
        self.assertEqual(action["effective_settings"]["extra_args"], ["--takeover", "False"])

    def test_root_cli_updates_subfinder_extra_args(self):
        result = self._run_json("cli.py", "-subfinder", "-recursive")
        action = result["actions"][0]["result"]
        self.assertEqual(action["effective_settings"]["extra_args"], ["-recursive"])

    def test_root_cli_updates_dirsearch_extra_args(self):
        result = self._run_json("cli.py", "-dirsearch", "--exclude-status 404")
        action = result["actions"][0]["result"]
        self.assertEqual(action["effective_settings"]["extra_args"], ["--exclude-status", "404"])

    def test_root_cli_reset_nmap(self):
        self._run_json("cli.py", "-nmap", "-sS -Pn")
        result = self._run_json("cli.py", "-reset", "nmap")
        action = result["actions"][0]["result"]
        self.assertNotEqual(action["settings"]["args"], ["-sS", "-Pn"])

    def test_root_cli_rejects_reserved_oneforall_args(self):
        result = self._run("cli.py", "-oneforall", "--fmt json")
        self.assertNotEqual(result.returncode, 0)
        error = json.loads(result.stdout)
        self.assertFalse(error["ok"])
        self.assertIn("保留参数", error["error"])

    def test_root_mcp_server_imports(self):
        result = self._run("-B", "-c", "import mcp_server; print(mcp_server.mcp.name)")
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        self.assertIn("selectinfo-tools", result.stdout)

    def test_tools_cli_shim_still_works(self):
        result = self._run_json("tools/cli.py", "-show")
        self.assertTrue(result["ok"])
        self.assertIn("show", result)

    def test_tools_mcp_shim_imports(self):
        result = self._run("-B", "-c", "import tools.mcp_server as m; print(m.mcp.name)")
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        self.assertIn("selectinfo-tools", result.stdout)


if __name__ == "__main__":
    unittest.main()
