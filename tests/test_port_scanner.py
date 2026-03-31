import unittest

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config
from core.port_scanner import PortScanner


class PortScannerTests(unittest.TestCase):
    def setUp(self):
        self._original_settings = config.load_local_settings()
        cleaned = dict(self._original_settings)
        cleaned.pop("tool_settings", None)
        config.save_local_settings(cleaned)

    def tearDown(self):
        config.save_local_settings(self._original_settings)

    def test_default_nmap_timeout_is_not_too_low(self):
        scanner = PortScanner()
        self.assertEqual(scanner.timeout, 600.0)

    def test_port_scanner_uses_effective_nmap_timeout_setting(self):
        config.set_tool_settings("nmap", {"timeout": 456.0})
        scanner = PortScanner()
        self.assertEqual(scanner.timeout, 456.0)


if __name__ == "__main__":
    unittest.main()
