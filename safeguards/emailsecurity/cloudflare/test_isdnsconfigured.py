import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("isdnsconfigured.py")


def load_transformation():
    spec = importlib.util.spec_from_file_location(
        "cloudflare_isdnsconfigured",
        TRANSFORMATION_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CloudflareDnsConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transformation = load_transformation()

    def assert_dns_state(self, response, *, spf, dkim, dmarc):
        transformed = response["transformedResponse"]
        self.assertEqual(transformed["isSPFConfigured"], spf)
        self.assertEqual(transformed["isDKIMConfigured"], dkim)
        self.assertEqual(transformed["isDMARCConfigured"], dmarc)
        self.assertEqual(
            transformed["isDNSConfigured"],
            spf and dkim and dmarc,
        )
        self.assertEqual(transformed["spfConfigured"], spf)
        self.assertEqual(transformed["dkimConfigured"], dkim)
        self.assertEqual(transformed["dmarcConfigured"], dmarc)

    def test_reads_actual_dns_helper_response(self):
        response = self.transformation.transform({
            "result": {
                "SPF": "v=spf1 -all",
                "DKIM": "v=DKIM1; p=public-key",
                "DMARC": "v=DMARC1; p=reject",
                "SMTPBanner": "No banner found",
            },
        })

        self.assert_dns_state(response, spf=True, dkim=True, dmarc=True)

    def test_partial_helper_response_does_not_pass_aggregate(self):
        response = self.transformation.transform({
            "result": {
                "SPF": "v=spf1 -all",
                "DKIM": False,
                "DMARC": "v=DMARC1; p=reject",
            },
        })

        self.assert_dns_state(response, spf=True, dkim=False, dmarc=True)

    def test_preserves_lowercase_direct_input(self):
        response = self.transformation.transform({
            "spf": True,
            "dkim": True,
            "dmarc": True,
        })

        self.assert_dns_state(response, spf=True, dkim=True, dmarc=True)

    def test_preserves_nested_email_authentication_input(self):
        response = self.transformation.transform({
            "settings": {
                "emailAuthentication": {
                    "spf": {"enabled": True},
                    "dkim": {"configured": True},
                    "dmarc": True,
                },
            },
        })

        self.assert_dns_state(response, spf=True, dkim=True, dmarc=True)

    def test_preserves_cloudflare_dns_record_input(self):
        response = self.transformation.transform({
            "records": [
                {"type": "TXT", "name": "example.com", "content": "v=spf1 -all"},
                {
                    "type": "TXT",
                    "name": "selector._domainkey.example.com",
                    "content": "v=DKIM1; p=public-key",
                },
                {
                    "type": "TXT",
                    "name": "_dmarc.example.com",
                    "content": "v=DMARC1; p=reject",
                },
            ],
        })

        self.assert_dns_state(response, spf=True, dkim=True, dmarc=True)


if __name__ == "__main__":
    unittest.main()
