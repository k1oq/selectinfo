import unittest

from _bootstrap import PROJECT_ROOT  # noqa: F401
from core.domain_extractor import DomainExtractor


class DomainExtractorTests(unittest.TestCase):
    def test_extract_registered_domain_from_url(self):
        self.assertEqual(
            DomainExtractor.extract("https://api.sub.example.com/path"),
            "example.com",
        )

    def test_extract_registered_domain_from_plain_host(self):
        self.assertEqual(
            DomainExtractor.extract("www.example.com"),
            "example.com",
        )

    def test_extract_handles_multi_part_suffix(self):
        self.assertEqual(
            DomainExtractor.extract("https://service.example.co.uk/login"),
            "example.co.uk",
        )

    def test_extract_full_returns_expected_parts(self):
        result = DomainExtractor.extract_full("https://api.sub.example.com/path")
        self.assertEqual(result["subdomain"], "api.sub")
        self.assertEqual(result["domain"], "example")
        self.assertEqual(result["suffix"], "com")
        self.assertEqual(result["registered_domain"], "example.com")

    def test_extract_keeps_ip_target(self):
        self.assertEqual(DomainExtractor.extract("https://1.1.1.1/login"), "1.1.1.1")
        self.assertTrue(DomainExtractor.is_ip_target("1.1.1.1"))

    def test_extract_full_marks_ip_target(self):
        result = DomainExtractor.extract_full("1.1.1.1")
        self.assertTrue(result["is_ip"])
        self.assertEqual(result["registered_domain"], "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
