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
        self.assertIn("--preset", result.stdout)
        self.assertIn("--tools", result.stdout)
        self.assertIn("--skip-wildcard", result.stdout)
        self.assertIn("--skip-validation", result.stdout)
        self.assertIn("--serial", result.stdout)
        self.assertIn("--reverse-ip", result.stdout)
        self.assertIn("--no-reverse-ip", result.stdout)
        self.assertIn("常用示例", result.stdout)
        self.assertNotIn("--_background-child", result.stdout)
        self.assertNotIn("--_job-id", result.stdout)
        self.assertNotIn("--_status-file", result.stdout)
        self.assertNotIn("--_log-file", result.stdout)


if __name__ == "__main__":
    unittest.main()
