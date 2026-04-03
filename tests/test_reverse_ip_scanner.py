import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
from core.reverse_ip_scanner import (
    ReverseIPScanner,
    merge_reverse_ip_into_scan_result,
    persist_reverse_ip_enrichment,
)


class ReverseIPScannerTests(unittest.TestCase):
    def test_scan_collects_ptr_and_tls_candidates(self):
        scanner = ReverseIPScanner(timeout=1, tls_ports=[443, 8443])

        def resolve_hostname(hostname: str) -> list[str]:
            mapping = {
                "ptr.example.com": ["1.1.1.1"],
                "www.example.com": ["1.1.1.1"],
                "old.example.com": ["2.2.2.2"],
            }
            return mapping.get(hostname, [])

        with mock.patch.object(scanner, "_lookup_ptr", return_value=["ptr.example.com"]), mock.patch.object(
            scanner,
            "_fetch_tls_names",
            side_effect=lambda _ip, port: ["www.example.com", "old.example.com"] if port == 443 else [],
        ), mock.patch.object(scanner, "_resolve_hostname", side_effect=resolve_hostname):
            result = scanner.scan("1.1.1.1", open_ports=[80, 443, 8443])

        self.assertEqual(result["target_ip"], "1.1.1.1")
        self.assertEqual(result["ports_checked"], [443, 8443])
        self.assertEqual(result["statistics"]["candidate_count"], 3)
        self.assertEqual(result["statistics"]["current_match_count"], 2)
        self.assertEqual(result["statistics"]["source_counts"]["ptr"], 1)
        self.assertEqual(result["statistics"]["source_counts"]["tls_cert"], 2)

        domains = {item["domain"]: item for item in result["domains"]}
        self.assertEqual(domains["ptr.example.com"]["confidence"], "medium")
        self.assertEqual(domains["www.example.com"]["ports"], [443])
        self.assertFalse(domains["old.example.com"]["matches_target"])

    def test_merge_reverse_ip_into_scan_result_appends_current_matches(self):
        scan_result = {
            "target": "1.1.1.1",
            "subdomains": [{"subdomain": "1.1.1.1", "ip": ["1.1.1.1"], "alive_verified": True}],
            "statistics": {"total_found": 1, "valid_count": 1, "total_unique": 1},
        }
        reverse_result = {
            "domains": [
                {
                    "domain": "reverse.example.com",
                    "sources": ["ptr", "tls_cert"],
                    "ports": [443],
                    "resolved_ips": ["1.1.1.1"],
                    "matches_target": True,
                },
                {
                    "domain": "stale.example.com",
                    "sources": ["ptr"],
                    "ports": [],
                    "resolved_ips": ["2.2.2.2"],
                    "matches_target": False,
                },
            ]
        }

        merged = merge_reverse_ip_into_scan_result(scan_result, reverse_result)

        self.assertEqual(len(merged["subdomains"]), 2)
        self.assertTrue(any(item["subdomain"] == "reverse.example.com" for item in merged["subdomains"]))
        self.assertFalse(any(item["subdomain"] == "stale.example.com" for item in merged["subdomains"]))
        self.assertEqual(merged["statistics"]["total_found"], 2)
        self.assertEqual(merged["statistics"]["total_unique"], 2)

    def test_persist_reverse_ip_enrichment_updates_saved_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.json"
            path.write_text(
                json.dumps(
                    {
                        "target": "1.1.1.1",
                        "subdomains": [{"subdomain": "1.1.1.1", "ip": ["1.1.1.1"]}],
                        "statistics": {"total_found": 1, "valid_count": 1},
                    }
                ),
                encoding="utf-8",
            )
            scan_result = {
                "reverse_ip": {"domains": [{"domain": "reverse.example.com"}]},
                "subdomains": [{"subdomain": "reverse.example.com", "ip": ["1.1.1.1"]}],
                "statistics": {"total_found": 1, "valid_count": 1},
            }

            persist_reverse_ip_enrichment(path, scan_result)
            data = json.loads(path.read_text(encoding="utf-8"))

        self.assertIn("reverse_ip", data)
        self.assertEqual(data["subdomains"][0]["subdomain"], "reverse.example.com")


if __name__ == "__main__":
    unittest.main()
