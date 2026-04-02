import subprocess
import sys
import unittest
from pathlib import Path

from _bootstrap import PROJECT_ROOT  # noqa: F401


class EntrypointTests(unittest.TestCase):
    def setUp(self):
        self.project_root = Path(PROJECT_ROOT)

    def _run(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *args],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_scan_entrypoint_help_renders(self):
        result = self._run("scan.py", "--help")
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        self.assertIn("SelectInfo", result.stdout)
        self.assertIn("--port-scan", result.stdout)
        self.assertIn("--nmap-args", result.stdout)
        self.assertIn("--subfinder-args", result.stdout)

    def test_root_mcp_server_imports(self):
        result = self._run("-B", "-c", "import mcp_server; print(mcp_server.mcp.name)")
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        self.assertIn("selectinfo-tools", result.stdout)

    def test_tools_mcp_shim_imports(self):
        result = self._run("-B", "-c", "import tools.mcp_server as m; print(m.mcp.name)")
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
        self.assertIn("selectinfo-tools", result.stdout)


if __name__ == "__main__":
    unittest.main()
