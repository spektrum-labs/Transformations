"""Google Workspace isDNSConfigured: DMARC, SPF and DKIM judged on enforcing strength.

The three criteria answer whether the published records ENFORCE. Until 2026-10-07 they
answered whether a non-empty string came back, so a domain at v=DMARC1;p=none with
v=spf1 ?all was told DMARC and SPF were configured. The requirements behind these keys
ask for enforcement in their own words -- "DMARC at quarantine or reject", "set for at
least soft reject", "SPF is strictly enforced".

Every record used here is a published example from RFC 7489, RFC 7208, RFC 6376 or from
Microsoft's and Google's own documentation, with example.com in place of a domain. DNS
TXT records are public facts; nothing here came from a tenant.

Each assertion checks the VALUE and dataCollection.status together. Checking the value
alone would pass a None under "success", which Token-Service compares, grades FAILED and
writes a gap for -- the exact failure this change exists to remove.
"""
import importlib.util
import unittest
from pathlib import Path

TRANSFORMATION_PATH = Path(__file__).with_name("isdnsconfigured.py")

SPF = "isSPFConfigured"
DMARC = "isDMARCConfigured"
DKIM = "isDKIMConfigured"
DNS = "isDNSConfigured"
KEYS = (SPF, DMARC, DKIM, DNS)

# Microsoft's documented record for a Microsoft-365-only domain.
MS_SPF = "v=spf1 include:spf.protection.outlook.com -all"
# Google's documented record. Google recommends ~all, not -all.
GOOGLE_SPF = "v=spf1 include:_spf.google.com ~all"
# A DKIM public-key record in the form RFC 6376 s3.6.1 defines.
DKIM_TXT = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDexample"
# Microsoft publishes DKIM selectors as CNAMEs, so the probe sees a target, not a record.
DKIM_CNAME = "selector1-example-com._domainkey.example.n-v1.dkim.mail.microsoft"


def load_transformation():
    spec = importlib.util.spec_from_file_location("google_isdnsconfigured", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises: the only route into except."""

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def get(self, *args, **kwargs):
        raise RuntimeError("poisoned")

    def keys(self):
        raise RuntimeError("poisoned")

    def items(self):
        raise RuntimeError("poisoned")

    def __getitem__(self, key):
        raise RuntimeError("poisoned")

    def __contains__(self, key):
        raise RuntimeError("poisoned")

    def __iter__(self):
        raise RuntimeError("poisoned")


class GoogleDnsEnforcementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    # -- helpers ---------------------------------------------------------------

    def run_transform(self, payload):
        return self.t.transform(payload)

    def values(self, response):
        return response["transformedResponse"]

    def status(self, response):
        return response["additionalInfo"]["dataCollection"]["status"]

    def assert_measured(self, response, **expected):
        """Assert the value AND that the response claims to have measured it."""
        self.assertEqual(self.status(response), "success")
        for key, want in expected.items():
            self.assertIs(self.values(response)[key], want, key)

    def assert_not_measured(self, response, *keys):
        """A None criterion must arrive as dataCollection error, or it grades as a gap."""
        self.assertEqual(self.status(response), "error")
        self.assertTrue(response["additionalInfo"]["dataCollection"]["errors"])
        for key in keys:
            self.assertIsNone(self.values(response)[key], key)

    # -- enforcing records pass -------------------------------------------------

    def test_hard_fail_spf_and_reject_dmarc_pass(self):
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT,
              "DMARC": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"})
        self.assert_measured(response, isSPFConfigured=True, isDMARCConfigured=True,
                             isDKIMConfigured=True, isDNSConfigured=True)

    def test_google_soft_fail_spf_passes(self):
        # Google's own guidance is ~all. Requiring -all would fail every tenant that
        # followed it, so ~all clears the bar and the hard-fail distinction is reported.
        response = self.run_transform(
            {"SPF": GOOGLE_SPF, "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=quarantine"})
        self.assert_measured(response, isSPFConfigured=True, isDNSConfigured=True)
        self.assertEqual(
            response["additionalInfo"]["transformation"]["inputSummary"]["spfAllMechanism"],
            "~all")
        self.assertIs(
            response["additionalInfo"]["transformation"]["inputSummary"]["spfHardFail"], False)

    def test_microsoft_dkim_cname_counts_as_published(self):
        # Microsoft documents CNAME selectors, not a v=DKIM1 TXT record, so a selector
        # target is the only DKIM evidence the probe can return for an M365 domain.
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_CNAME, "DMARC": "v=DMARC1; p=reject"})
        self.assert_measured(response, isDKIMConfigured=True, isDNSConfigured=True)

    # -- the defect this change removes ----------------------------------------

    def test_dmarc_p_none_is_not_configured(self):
        # RFC 7489 s6.3: p=none "requests no specific action be taken".
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=none; rua=mailto:d@example.com"})
        self.assert_measured(response, isDMARCConfigured=False, isDNSConfigured=False)
        self.assertTrue(response["additionalInfo"]["evaluation"]["failReasons"])

    def test_spf_neutral_all_is_not_configured(self):
        # RFC 7208 s8.2: a neutral result "MUST be treated exactly like the none result".
        response = self.run_transform(
            {"SPF": "v=spf1 include:spf.example.com ?all", "DKIM": DKIM_TXT,
              "DMARC": "v=DMARC1; p=reject"})
        self.assert_measured(response, isSPFConfigured=False, isDNSConfigured=False)

    def test_spf_plus_all_is_not_configured(self):
        response = self.run_transform(
            {"SPF": "v=spf1 +all", "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=reject"})
        self.assert_measured(response, isSPFConfigured=False)

    def test_spf_without_an_all_mechanism_is_not_configured(self):
        # RFC 7208 s4.7: with no matching mechanism the default result is neutral.
        response = self.run_transform(
            {"SPF": "v=spf1 include:spf.example.com", "DKIM": DKIM_TXT,
              "DMARC": "v=DMARC1; p=reject"})
        self.assert_measured(response, isSPFConfigured=False)

    def test_arbitrary_string_is_not_an_spf_record(self):
        # The helper this replaced passed any non-empty string outside a short stop-list.
        response = self.run_transform(
            {"SPF": "some text that is not a record", "DKIM": DKIM_TXT,
              "DMARC": "v=DMARC1; p=reject"})
        self.assert_measured(response, isSPFConfigured=False)

    def test_the_first_all_mechanism_decides_not_the_last(self):
        # RFC 7208 s4.6.2: mechanisms are evaluated left to right and "if it matches,
        # processing ends and the qualifier value is returned". "all" always matches, so
        # a receiver seeing "v=spf1 +all -all" applies +all and the -all is unreachable.
        for record in ("v=spf1 +all -all", "v=spf1 ?all -all", "v=spf1 all ~all"):
            response = self.run_transform(
                {"SPF": record, "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=reject"})
            self.assert_measured(response, isSPFConfigured=False, isDNSConfigured=False)
            summary = response["additionalInfo"]["transformation"]["inputSummary"]
            self.assertEqual(summary["spfUnreachableAllTerms"], ["-all"] if "-all" in record
                             else ["~all"], record)

    def test_a_version_section_of_v_spf10_is_discarded(self):
        # RFC 7208 s4.5 names this exact case: "a record with a version section of
        # 'v=spf10' does not match and is discarded". startswith("v=spf1") accepted it.
        response = self.run_transform(
            {"SPF": "v=spf10 -all", "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=reject"})
        self.assert_measured(response, isSPFConfigured=False, isDNSConfigured=False)

    def test_dmarc_record_without_v_tag_is_ignored(self):
        # RFC 7489 s6.3: without v=DMARC1 "the entire retrieved record MUST be ignored".
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT, "DMARC": "p=reject; rua=mailto:d@example.com"})
        self.assert_measured(response, isDMARCConfigured=False)

    # -- pct and sp, per RFC 7489 s6.6.4 and s6.3 -------------------------------

    def test_quarantine_below_full_pct_does_not_enforce(self):
        # s6.6.4: mail outside a quarantine sample gets "local message classification as
        # normal", so the weakest treatment under p=quarantine; pct=25 is none.
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT,
              "DMARC": "v=DMARC1; p=quarantine; rua=mailto:d@example.com; pct=25"})
        self.assert_measured(response, isDMARCConfigured=False)

    def test_reject_below_full_pct_still_clears_the_quarantine_bar(self):
        # s6.6.4: mail outside a reject sample is treated "as though the quarantine
        # policy applies", so reject at any pct never falls below quarantine.
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=reject; pct=25"})
        self.assert_measured(response, isDMARCConfigured=True)

    def test_subdomain_policy_none_does_not_enforce(self):
        # s6.3: sp "applies only to subdomains" in place of p, so sp=none leaves every
        # sending subdomain unprotected while the organizational domain looks compliant.
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=reject; sp=none"})
        self.assert_measured(response, isDMARCConfigured=False)

    def test_subdomain_policy_quarantine_enforces(self):
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=reject; sp=quarantine"})
        self.assert_measured(response, isDMARCConfigured=True)

    def test_malformed_pct_is_ignored_not_guessed_at(self):
        # s6.4 bounds pct at 0-100. A malformed value is not a smaller percentage.
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": DKIM_TXT, "DMARC": "v=DMARC1; p=quarantine; pct=abc"})
        self.assert_measured(response, isDMARCConfigured=True)

    # -- DKIM, RFC 6376 ---------------------------------------------------------

    def test_revoked_dkim_key_is_not_configured(self):
        # s6.1.2 step 7: an empty p= means the key has been revoked, and there is "no
        # defined semantic difference between a key that has been revoked and a key
        # record that has been removed".
        response = self.run_transform(
            {"SPF": MS_SPF, "DKIM": "v=DKIM1; k=rsa; p=", "DMARC": "v=DMARC1; p=reject"})
        self.assert_measured(response, isDKIMConfigured=False, isDNSConfigured=False)

    def test_no_records_published_is_a_measured_fail(self):
        # The probe looked and found nothing. That is a measurement, not a silence.
        response = self.run_transform(
            {"SPF": False, "DKIM": False, "DMARC": False, "SMTPBanner": "No banner found"})
        self.assert_measured(response, isSPFConfigured=False, isDMARCConfigured=False,
                             isDKIMConfigured=False, isDNSConfigured=False)

    def test_negative_sentinel_strings_are_a_measured_fail(self):
        # Each of these NAMES AN ABSENCE, so each is a measured absence. "N/A" is not
        # here any more: it says the probe has no answer, which is a different thing.
        response = self.run_transform({"SPF": "not found", "DKIM": "None", "DMARC": "no record"})
        self.assert_measured(response, isSPFConfigured=False, isDMARCConfigured=False,
                             isDKIMConfigured=False)

    def test_nxdomain_is_a_measured_absence(self):
        # RFC 7208 s4.4: "Name Error" (RCODE 3 / NXDOMAIN) returns "none" -- the name
        # does not exist, so no record is published. That is a measurement.
        response = self.run_transform({"SPF": "NXDOMAIN", "DKIM": "NXDOMAIN", "DMARC": "NXDOMAIN"})
        self.assert_measured(response, isSPFConfigured=False, isDMARCConfigured=False,
                             isDKIMConfigured=False, isDNSConfigured=False)

    # -- not measured -----------------------------------------------------------

    def test_unknown_and_not_available_are_not_measured(self):
        # "unknown" is not "no record is published". Scoring it as an absence writes a
        # real gap out of nothing -- the same defect as scoring a string as proof, in
        # the other direction.
        response = self.run_transform(
            {"SPF": "unknown", "DMARC": "not available", "DKIM": "n/a"})
        self.assert_not_measured(response, SPF, DMARC, DKIM, DNS)

    def test_a_resolver_failure_is_not_measured(self):
        # RFC 7208 s4.4: a server failure, any RCODE other than 0 or 3, or a timeout is
        # "temperror", which asserts nothing about what the domain publishes.
        response = self.run_transform(
            {"SPF": "timeout", "DMARC": "SERVFAIL", "DKIM": "Error: query refused"})
        self.assert_not_measured(response, SPF, DMARC, DKIM, DNS)

    def test_a_record_naming_a_host_called_error_is_still_a_record(self):
        # The probe-failure heuristic is tested only on values that do not open a
        # version section, so a legitimate record is never mistaken for an error.
        response = self.run_transform(
            {"SPF": "v=spf1 include:mail-error.example.com -all", "DMARC": "v=DMARC1; p=reject",
             "DKIM": DKIM_TXT})
        self.assert_measured(response, isSPFConfigured=True, isDMARCConfigured=True,
                             isDKIMConfigured=True, isDNSConfigured=True)

    def test_a_dkim_answer_that_is_neither_a_record_nor_a_selector_is_not_measured(self):
        # Until this change, any non-empty DKIM string outside the stop-list returned
        # True on the Microsoft CNAME branch, so a probe error came out as a measured
        # green -- the one place this file still said "non-empty string = configured".
        for junk in ("Error: SERVFAIL querying selector1._domainkey",
                     "timed out",
                     "lookup produced no usable answer",
                     "selector1"):
            response = self.run_transform(
                {"SPF": MS_SPF, "DMARC": "v=DMARC1; p=reject", "DKIM": junk})
            self.assert_not_measured(response, DKIM, DNS)
            self.assertIs(self.values(response)[SPF], True, junk)

    def test_a_dkim_cname_target_is_still_presence_only_proof(self):
        # The presence-only branch exists for the CNAME selector model and must survive.
        for target in (DKIM_CNAME,
                       "selector1-example-com._domainkey.example.onmicrosoft.com",
                       "abc123._domainkey.example-com.dkim.mimecast.com"):
            response = self.run_transform(
                {"SPF": MS_SPF, "DMARC": "v=DMARC1; p=reject", "DKIM": target})
            self.assert_measured(response, isDKIMConfigured=True, isDNSConfigured=True)

    def test_measured_failures_keep_their_reasons_when_a_sibling_is_unreadable(self):
        # dataCollection.status is per RESPONSE, so an unreadable DKIM withholds the
        # grade from SPF and DMARC too -- that is the accepted trade-off, because the
        # other arrangement grades a None and ships an unmeasured control as a gap.
        # What must NOT also happen is the response losing the sentences that say which
        # protocol failed and why.
        response = self.run_transform({"SPF": "v=spf1 +all", "DMARC": "v=DMARC1; p=none"})
        self.assert_not_measured(response, DKIM, DNS)
        self.assertIs(self.values(response)[SPF], False)
        self.assertIs(self.values(response)[DMARC], False)
        reasons = response["additionalInfo"]["evaluation"]["failReasons"]
        self.assertTrue(reasons, "the measured failures lost their reasons")
        self.assertTrue(any("all-mechanism" in r for r in reasons))
        self.assertTrue(any("p=none" in r for r in reasons))
        # and no "we could not read it" sentence is filed as a finding
        self.assertFalse(any("not measured" in r for r in reasons))
        rows = {row["metric"]: row["status"]
                for row in response["additionalInfo"]["evaluation"]["additionalFindings"]
                if "metric" in row}
        self.assertEqual(rows[SPF], "fail")
        self.assertEqual(rows[DMARC], "fail")
        self.assertEqual(rows[DKIM], "notMeasured")

    def test_presence_without_the_record_is_not_measured_for_spf_and_dmarc(self):
        # A bare True is "I did not find it off", not "I measured the control".
        response = self.run_transform({"SPF": True, "DKIM": True, "DMARC": True})
        self.assert_not_measured(response, SPF, DMARC, DNS)
        self.assertIs(self.values(response)[DKIM], True)

    def test_spf_redirect_without_an_all_mechanism_is_not_measured(self):
        # RFC 7208 s6.1 puts the effective policy in the redirected record, which this
        # probe does not resolve.
        response = self.run_transform(
            {"SPF": "v=spf1 redirect=_spf.example.com", "DKIM": DKIM_TXT,
              "DMARC": "v=DMARC1; p=reject"})
        self.assert_not_measured(response, SPF, DNS)

    def test_a_protocol_absent_from_the_body_is_not_measured(self):
        response = self.run_transform({"SPF": MS_SPF})
        self.assert_not_measured(response, DMARC, DKIM, DNS)
        self.assertIs(self.values(response)[SPF], True)

    def test_empty_body_is_not_measured(self):
        response = self.run_transform({})
        self.assert_not_measured(response, *KEYS)

    def test_none_body_is_not_measured(self):
        response = self.run_transform(None)
        self.assert_not_measured(response, *KEYS)

    def test_refusal_bodies_are_not_measured(self):
        for body in ({"statusCode": 401, "error": "Unauthorized"},
                     {"statusCode": 403, "error": "Forbidden"},
                     {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                     {"error": {"type": "authentication_error"}}):
            with self.subTest(body=body):
                self.assert_not_measured(self.run_transform(body), *KEYS)

    def test_unrelated_body_is_not_measured(self):
        # Absence of the field we read, not recognition of an envelope: one vendor's
        # error shape proves nothing about another's.
        self.assert_not_measured(self.run_transform({"hello": "world"}), *KEYS)

    def test_poisoned_body_reaches_except_and_is_not_measured(self):
        # The except branch records transformation_errors, which the grading path never
        # reads. Deriving the status from the value is what makes this branch correct.
        self.assert_not_measured(self.run_transform(Poisoned()), *KEYS)

    # -- wrapping ---------------------------------------------------------------

    def test_probe_body_nested_as_a_repr_string_is_read(self):
        # The stored shape: result.apiResponse.result holding a Python repr.
        payload = {"result": {"apiResponse": {"result":
                   "{'SPF': 'v=spf1 include:spf.example.com ~all', 'DKIM': False, "
                   "'DMARC': 'v=DMARC1;p=quarantine;pct=100;fo=1', "
                   "'SMTPBanner': 'No banner found'}"}}}
        response = self.run_transform(payload)
        self.assert_measured(response, isSPFConfigured=True, isDMARCConfigured=True,
                             isDKIMConfigured=False, isDNSConfigured=False)

    def test_enriched_input_with_failed_validation_is_not_measured(self):
        response = self.run_transform(
            {"data": {"SPF": MS_SPF}, "validation": {"status": "failed", "errors": ["bad"],
                                                     "warnings": []}})
        self.assert_not_measured(response, *KEYS)


if __name__ == "__main__":
    unittest.main()
