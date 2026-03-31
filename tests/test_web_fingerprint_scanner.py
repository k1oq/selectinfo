import unittest
from unittest.mock import patch

from _bootstrap import PROJECT_ROOT  # noqa: F401
from core.web_fingerprint_scanner import WebFingerprintScanner


HTTP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.25.0" extrainfo="demo" />
        <script id="http-title" output="Welcome" />
        <script id="http-server-header" output="nginx" />
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0" />
      </port>
    </ports>
  </host>
</nmaprun>
"""

HTTPS_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="http" tunnel="ssl" product="Apache" version="2.4.0" />
        <script id="ssl-cert" output="Subject: CN=demo.example.com&#10;Issuer: CN=Test CA" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


class WebFingerprintScannerTests(unittest.TestCase):
    def test_parse_ip_fingerprint_extracts_only_web_ports(self):
        scanner = WebFingerprintScanner(nmap_path="nmap")
        result = scanner._parse_ip_fingerprint(HTTP_XML)

        self.assertEqual(list(result.keys()), [80])
        self.assertEqual(result[80]["service"], "http")
        self.assertEqual(result[80]["title"], "Welcome")
        self.assertEqual(result[80]["server_header"], "nginx")

    def test_parse_https_xml_extracts_cert_fields(self):
        scanner = WebFingerprintScanner(nmap_path="nmap")
        result = scanner._parse_ip_fingerprint(HTTPS_XML)

        self.assertEqual(list(result.keys()), [443])
        self.assertIn("ssl/http", result[443]["service"])
        self.assertIn("CN=demo.example.com", result[443]["ssl_cert_subject"])
        self.assertIn("CN=Test CA", result[443]["ssl_cert_issuer"])

    def test_build_url_keeps_non_default_port(self):
        self.assertEqual(
            WebFingerprintScanner._build_url("app.example.com", "https", 8443),
            "https://app.example.com:8443",
        )

    def test_scan_counts_unique_ip_port_candidates(self):
        scanner = WebFingerprintScanner(nmap_path="nmap")
        subdomains = [
            {"subdomain": "a.example.com", "ip": ["1.1.1.1"]},
            {"subdomain": "b.example.com", "ip": ["1.1.1.1"]},
        ]
        port_scan_hosts = {"1.1.1.1": [80]}

        with patch.object(scanner, "_fingerprint_ip", return_value=(True, HTTP_XML)) as mocked:
            result = scanner.scan(subdomains, port_scan_hosts)

        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(result["statistics"]["candidate_endpoint_count"], 1)
        self.assertEqual(result["statistics"]["web_target_count"], 2)
        urls = sorted(target["url"] for target in result["targets"])
        self.assertEqual(urls, ["http://a.example.com", "http://b.example.com"])
        self.assertNotIn("dirsearch", result["targets"][0])


if __name__ == "__main__":
    unittest.main()
