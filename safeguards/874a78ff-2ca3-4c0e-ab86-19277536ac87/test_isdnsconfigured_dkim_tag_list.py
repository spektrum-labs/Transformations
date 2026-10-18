"""isDNSConfigured: a DKIM key record is a tag list, not only text that starts with v=DKIM1 or p=.

RFC 6376 section 3.6.1: a DKIM key record is a list of tag=value pairs separated by semicolons. Only p (the public
key) is required, v is optional, and k, t, s, h, n and g may come in any order. A record such as "k=rsa; t=s; p=..."
carries neither v=DKIM1 nor a leading p=, and the strict reading of the DNS answer (Not evaluated, never a stated
negative) wrongly read it as "no usable answer for DKIM", which switched off the DMARC, DKIM and SPF checks of every
integration that uses this transformation.

All bodies here are synthetic.
"""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("dns_dkim_tag_list", HERE / "isdnsconfigured.py")
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)

KEYS = ("isDNSConfigured", "isDMARCConfigured", "isDKIMConfigured", "isSPFConfigured")
SPF = "v=spf1 include:spf.example.invalid -all"
DMARC = "v=DMARC1; p=reject; rua=mailto:reports@example.invalid"
KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAexample+key/with=padding=="


def body(dkim, **extra):
    data = {"SPF": SPF, "DKIM": dkim, "DMARC": DMARC, "SMTPBanner": "No banner found"}
    data.update(extra)
    return data


class DkimTagListTests(unittest.TestCase):
    def check(self, payload):
        return DNS.transform(payload)

    def assert_measured(self, response):
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], [])

    def assert_not_evaluated(self, response):
        self.assertEqual(response["transformedResponse"], {key: None for key in KEYS})
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertIn("DKIM", response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_records_without_the_optional_v_tag_are_found(self):
        for record in (
            "k=rsa; t=s; p=" + KEY,                 # the shape that was read as "no usable answer"
            "k=rsa; p=" + KEY,
            "t=y; k=rsa; p=" + KEY,
            "k=rsa;p=" + KEY,                       # no spaces
            "  K=RSA; T=S; P=" + KEY + "  ",        # case and outer blanks
            "h=sha256; s=email; k=rsa; p=" + KEY + ";",   # trailing separator
            "k=ed25519; p=AAAAexamplekey",
            "n=note text; p=" + KEY,
        ):
            with self.subTest(record=record):
                response = self.check(body(record))
                self.assertEqual(response["transformedResponse"], {key: True for key in KEYS})
                self.assert_measured(response)

    def test_records_with_v_tag_still_pass(self):
        for record in ("v=DKIM1; k=rsa; p=" + KEY, "v=DKIM1;p=" + KEY, "k=rsa; V=DKIM1; p=" + KEY, "p=" + KEY):
            with self.subTest(record=record):
                response = self.check(body(record))
                self.assertIs(response["transformedResponse"]["isDKIMConfigured"], True)
                self.assert_measured(response)

    def test_a_tag_list_without_a_key_is_not_an_answer(self):
        """No p tag: nothing says whether a key is published, so the read is Not evaluated, never True."""
        for record in ("k=rsa; t=s", "k=rsa", "t=y", "v=DKIM1; k=rsa"):
            with self.subTest(record=record):
                self.assert_not_evaluated(self.check(body(record)))

    def test_a_v_tag_of_another_protocol_is_not_a_dkim_record(self):
        for record in (DMARC, "v=DMARC1; p=none", SPF, "v=spf1 -all", "v=BIMI1; l=https://example.invalid/logo.svg; p=x"):
            with self.subTest(record=record):
                self.assert_not_evaluated(self.check(body(record)))

    def test_text_that_is_not_a_tag_list_is_not_an_answer(self):
        for value in ("No DKIM record found.", "error", "k=rsa; broken; p=" + KEY, "k rsa; p=" + KEY, "=rsa; p=" + KEY,
                      "k=rsa p=" + KEY.replace("=", "") + " extra words", "", "   ", 0, 1, [], {}, None):
            with self.subTest(value=value):
                response = self.check(body(value))
                self.assert_not_evaluated(response)

    def test_a_revoked_key_is_a_measured_false(self):
        """An empty p tag revokes the key (RFC 6376): the record is there and no key is usable."""
        for record in ("v=DKIM1; k=rsa; p=", "k=rsa; t=s; p=", "p=", "k=rsa; p=   ;"):
            with self.subTest(record=record):
                response = self.check(body(record))
                self.assertEqual(response["transformedResponse"], {
                    "isDNSConfigured": False, "isDMARCConfigured": True, "isDKIMConfigured": False, "isSPFConfigured": True})
                self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Missing DNS records: DKIM"])
                self.assert_measured(response)

    def test_an_explicit_false_and_the_other_two_records_are_unchanged(self):
        response = self.check(body(False))
        self.assertIs(response["transformedResponse"]["isDKIMConfigured"], False)
        self.assertIs(response["transformedResponse"]["isDMARCConfigured"], True)
        self.assertIs(response["transformedResponse"]["isSPFConfigured"], True)
        self.assert_measured(response)
        for key, record in (("SPF", "k=rsa; t=s; p=" + KEY), ("DMARC", "k=rsa; t=s; p=" + KEY)):
            with self.subTest(key=key):
                response = self.check(body("k=rsa; p=" + KEY, **{key: record}))
                self.assertEqual(response["transformedResponse"], {name: None for name in KEYS})
                self.assertIn(key, response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_input_forms_reach_the_same_answer(self):
        import json
        payload = body("k=rsa; t=s; p=" + KEY)
        for form in (payload, json.dumps(payload), json.dumps(payload).encode("utf-8"), {"result": payload},
                     {"apiResponse": payload}):
            with self.subTest(form=type(form).__name__):
                self.assertEqual(self.check(form)["transformedResponse"], {key: True for key in KEYS})


if __name__ == "__main__":
    unittest.main()
