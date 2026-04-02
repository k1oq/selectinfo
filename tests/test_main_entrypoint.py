import tempfile
import unittest
from pathlib import Path

from _bootstrap import PROJECT_ROOT  # noqa: F401
import main


class MainEntrypointTests(unittest.TestCase):
    def test_background_command_includes_selected_preset(self):
        with tempfile.TemporaryDirectory() as tmp:
            job_dir = Path(tmp)
            plan = main.ScanExecutionPlan(
                targets=["example.com"],
                tools=["subfinder", "oneforall"],
                preset="deep",
                enable_port_scan=True,
                port_scan_mode="common",
                enable_web_fingerprint=True,
            )
            job = {
                "job_id": "scan_123",
                "job_dir": job_dir,
                "status_path": job_dir / "status.json",
                "log_path": job_dir / "scan.log",
            }

            command = main._build_background_scan_command(plan, job)

        self.assertIn("--preset", command)
        preset_index = command.index("--preset")
        self.assertEqual(command[preset_index + 1], "deep")
        self.assertNotIn("--tools", command)
        self.assertNotIn("--skip-wildcard", command)
        self.assertNotIn("--skip-validation", command)
        self.assertNotIn("--serial", command)


if __name__ == "__main__":
    unittest.main()
