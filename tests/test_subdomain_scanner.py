import unittest
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
from core.subdomain_scanner import SubdomainScanner


class SubdomainScannerTests(unittest.TestCase):
    def test_scan_direct_ip_skips_subdomain_tools(self):
        scanner = SubdomainScanner()

        with mock.patch.object(scanner.tool_manager, "get_all_tools") as get_all_tools:
            result = scanner.scan("1.1.1.1", tools=[])

        get_all_tools.assert_not_called()
        self.assertEqual(result["target"], "1.1.1.1")
        self.assertEqual(result["target_type"], "ip")
        self.assertEqual(result["tools_used"], [])
        self.assertEqual(result["subdomains"][0]["ip"], ["1.1.1.1"])
        self.assertTrue(result["subdomains"][0]["alive_verified"])


if __name__ == "__main__":
    unittest.main()
