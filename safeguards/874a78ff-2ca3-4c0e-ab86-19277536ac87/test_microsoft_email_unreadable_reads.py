"""Microsoft Email Security: an unreadable DNS, sign-in or licence read is Not evaluated, never a stated negative.

isDNSConfigured (DNS helper POST), isEmailSecurityLoggingEnabled (GET /auditLogs/signIns) and
confirmedLicensePurchased (GET /subscribedSkus) used to return False for a body that proved nothing: an empty body,
a helper outage, a Graph error, malformed JSON, failed input validation. A False is a stated negative; the platform
grades a collection error as Not evaluated only when the value is None.

All bodies here are synthetic.
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location("ms_email_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DNS = load("isdnsconfigured")
LOGGING = load("isemailsecurityloggingenabled")
LICENCE = load("confirmedlicensepurchased_exchange")

DNS_KEYS = ("isDNSConfigured", "isDMARCConfigured", "isDKIMConfigured", "isSPFConfigured")
LOGGING_KEYS = ("isEmailSecurityLoggingEnabled", "isEmailLoggingEnabled")
LICENCE_KEYS = ("confirmedLicensePurchased",)

GRAPH_403 = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}}
GRAPH_NONPREMIUM = {"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                              "message": "Neither tenant is B2C or tenant doesn't have premium license"}}
HELPER_503 = {"error": True, "errorType": "dns_unavailable", "status": "Error",
              "message": "DNS evaluation is temporarily unavailable", "statusCode": 503}

GOOD_DNS = {"SPF": "v=spf1 include:spf.example.invalid -all", "DKIM": "v=DKIM1; k=rsa; p=AAAA",
            "DMARC": "v=DMARC1; p=reject", "SMTPBanner": "No banner found"}
NO_RECORDS = {"SPF": False, "DKIM": False, "DMARC": False, "SMTPBanner": "No banner found"}
SIGN_IN = {"id": "sign-in-1", "createdDateTime": "2026-01-01T00:00:00Z",
           "appDisplayName": "Example App", "userPrincipalName": "user@example.invalid"}



def sku(part, plans, status="Enabled", enabled=25, provisioning="Success"):
    return {"skuPartNumber": part, "capabilityStatus": status, "prepaidUnits": {"enabled": enabled, "suspended": 0},
            "servicePlans": [{"servicePlanName": plan, "provisioningStatus": provisioning} for plan in plans]}


MAIL_SKU = sku("EXAMPLE_MAIL_PLAN", ["EXCHANGE_S_ENTERPRISE", "SHAREPOINTENTERPRISE"])
FREE_SKU = sku("EXAMPLE_FREE_PLAN", ["EXAMPLE_VIRAL_PLAN", "EXCHANGE_S_FOUNDATION"], enabled=10000)
UNREADABLE_ROW = {"skuPartNumber": "EXAMPLE_ROW_WITHOUT_PLANS"}
NEXT_LINK = "https://graph.example.invalid/v1.0/page?$skiptoken=page-2"
LINK_KEYS = ("@odata.nextLink", "odata.nextLink", "nextLink")
PASSED = {"status": "passed", "errors": [], "warnings": []}

VALIDATION_FAILED = {"data": {}, "validation": {"status": "failed", "errors": ["unexpected shape"], "warnings": []}}


class Unreadable(dict):
    """A body whose read raises with a long message, to reach the exception path."""

    def __contains__(self, key):
        raise ValueError("unreadable " * 100)

    def get(self, key, default=None):
        raise ValueError("unreadable " * 100)


class Checks(unittest.TestCase):
    module = None
    keys = ()

    def run_check(self, payload):
        return self.module.transform(payload)

    def assert_not_evaluated(self, response):
        """No value beside an error: every key None and a collection error, so the platform grades it Not evaluated."""
        self.assertEqual(response["transformedResponse"], {key: None for key in self.keys})
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(response["additionalInfo"]["dataCollection"]["errors"])

    def assert_measured(self, response):
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], [])


class DnsTests(Checks):
    module = DNS
    keys = DNS_KEYS

    # --- measured answers -------------------------------------------------------------------------------

    def test_all_three_records_pass(self):
        response = self.run_check(GOOD_DNS)

        self.assertEqual(response["transformedResponse"], {key: True for key in DNS_KEYS})
        self.assert_measured(response)

    def test_a_missing_record_is_a_measured_fail(self):
        response = self.run_check(dict(GOOD_DNS, DKIM=False))

        self.assertEqual(response["transformedResponse"], {
            "isDNSConfigured": False, "isDMARCConfigured": True, "isDKIMConfigured": False, "isSPFConfigured": True})
        self.assert_measured(response)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Missing DNS records: DKIM"])

    def test_a_helper_answer_of_no_records_is_a_measured_fail(self):
        """The helper answered, and every record is absent: a stated negative, not an unreadable body."""
        for payload in (NO_RECORDS, {"result": NO_RECORDS}, {"SPF": False, "DKIM": False, "DMARC": False}):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assertEqual(response["transformedResponse"], {key: False for key in DNS_KEYS})
                self.assert_measured(response)

    def test_the_other_input_shapes_are_read_alike(self):
        for label, payload in (
            ("plain", GOOD_DNS),
            ("result envelope", {"result": GOOD_DNS}),
            ("response envelope", {"response": GOOD_DNS}),
            ("enriched", {"data": GOOD_DNS, "validation": {"status": "passed", "errors": [], "warnings": []}}),
            ("json string", json.dumps(GOOD_DNS)),
            ("json bytes", json.dumps(GOOD_DNS).encode("utf-8")),
            ("lower-case keys", {"spf": GOOD_DNS["SPF"], "dkim": GOOD_DNS["DKIM"], "dmarc": GOOD_DNS["DMARC"]}),
        ):
            with self.subTest(shape=label):
                self.assertIs(self.run_check(payload)["transformedResponse"]["isDNSConfigured"], True)

    def test_a_record_that_is_present_counts_whatever_its_policy(self):
        """Presence only: a monitoring-only policy or a permissive SPF still reads configured, as before."""
        for label, body in (
            ("DMARC p=none", dict(GOOD_DNS, DMARC="v=DMARC1; p=none")),
            ("DMARC without a policy", dict(GOOD_DNS, DMARC="v=DMARC1")),
            ("SPF +all", dict(GOOD_DNS, SPF="v=spf1 +all")),
        ):
            with self.subTest(case=label):
                self.assertIs(self.run_check(body)["transformedResponse"]["isDNSConfigured"], True)

    # --- Not evaluated ----------------------------------------------------------------------------------

    def test_a_body_with_no_record_answer_is_not_evaluated(self):
        for payload in (
            {},
            {"result": {}},
            {"detail": "Internal Server Error"},
            HELPER_503,
            GRAPH_403,
            {"SMTPBanner": "No banner found"},
            {"SPF": None, "DKIM": None, "DMARC": None},
            [],
            [1, 2],
            "[]",
            "3",
            "null",
        ):
            with self.subTest(payload=payload):
                self.assert_not_evaluated(self.run_check(payload))

    def test_a_partial_answer_is_not_evaluated(self):
        """The lookup always answers all three keys (a record, or an explicit false when none was found), so a key
        that is absent or null means the body is not that answer, not that the record is absent."""
        for payload, missing in (
            ({"SPF": GOOD_DNS["SPF"]}, ("DKIM", "DMARC")),
            ({"DMARC": GOOD_DNS["DMARC"]}, ("SPF", "DKIM")),
            ({"SPF": GOOD_DNS["SPF"], "DKIM": None, "DMARC": GOOD_DNS["DMARC"]}, ("DKIM",)),
            ({"result": {"SPF": GOOD_DNS["SPF"], "DKIM": GOOD_DNS["DKIM"]}}, ("DMARC",)),
            ({"spf": GOOD_DNS["SPF"], "dkim": GOOD_DNS["DKIM"]}, ("DMARC",)),
            ({"SPF": False, "DKIM": False}, ("DMARC",)),
        ):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                error = response["additionalInfo"]["dataCollection"]["errors"][0]
                for name in missing:
                    self.assertIn(name, error)

    def test_a_value_that_is_neither_a_flag_nor_a_record_is_not_evaluated(self):
        """A flag (true or false) or the protocol's own record text is an answer. Words such as "error" or "missing",
        stand-in words, empty text, numbers, lists and objects are not, so they are neither a record found nor one
        absent."""
        for bad in ("false", "False", " FALSE ", "true", "0", "1", "", "  ", "none", "None", "null", "no", "n/a",
                    "not found", "No banner found", "error", "Error", "timeout", "missing", "unknown",
                    "not configured", "no record", "No DKIM record found.", "present", "configured", "example",
                    0, 1, 1.5, [], ["v=spf1 -all"], {}, {"record": "v=spf1 -all"}):
            for name in ("SPF", "DKIM", "DMARC"):
                with self.subTest(value=bad, key=name):
                    response = self.run_check(dict(GOOD_DNS, **{name: bad}))
                    self.assert_not_evaluated(response)
                    self.assertIn(name, response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_a_record_of_another_protocol_is_not_an_answer(self):
        """The text counts only when it is the record form of the key it sits under."""
        records = {"SPF": GOOD_DNS["SPF"], "DKIM": GOOD_DNS["DKIM"], "DMARC": GOOD_DNS["DMARC"]}
        for name in records:
            for other, record in records.items():
                if other == name:
                    continue
                with self.subTest(key=name, record_of=other):
                    response = self.run_check(dict(GOOD_DNS, **{name: record}))
                    self.assert_not_evaluated(response)
                    self.assertIn(name, response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_a_flag_or_the_protocols_own_record_text_is_an_answer(self):
        for name, value, expected in (
            ("SPF", True, True), ("SPF", False, False), ("DKIM", True, True), ("DMARC", False, False),
            ("SPF", "v=spf1 -all", True), ("SPF", "  V=SPF1 include:spf.example.invalid ~all  ", True),
            ("DMARC", "V=DMARC1; p=reject", True), ("DMARC", "  v=dmarc1; p=none", True),
            ("DKIM", "v=DKIM1; k=rsa; p=AAAA", True), ("DKIM", "k=rsa; V=DKIM1; p=AAAA", True), ("DKIM", "p=AAAA", True),
            ("DKIM", "  P=AAAA", True),
        ):
            with self.subTest(key=name, value=value):
                response = self.run_check(dict(GOOD_DNS, **{name: value}))
                self.assertIs(response["transformedResponse"]["is%sConfigured" % name], expected)
                self.assert_measured(response)

    def test_malformed_json_is_not_evaluated_with_a_transformation_error(self):
        for payload in ("Service Unavailable", "{not-json", b"\xff\xfe"):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")
                self.assertTrue(response["additionalInfo"]["transformation"]["errors"])

    def test_a_vendor_error_marker_is_not_evaluated(self):
        response = self.run_check({"PSError": "HTTP 503 Service Unavailable"})

        self.assert_not_evaluated(response)
        self.assertIn("Service unavailable", response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_failed_input_validation_is_not_evaluated(self):
        response = self.run_check(VALIDATION_FAILED)

        self.assert_not_evaluated(response)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Input validation failed"])

    def test_a_long_exception_message_is_capped(self):
        """The exception text reaches the stored result, so a long one is cut."""
        response = self.run_check(Unreadable())

        self.assert_not_evaluated(response)
        errors = response["additionalInfo"]["transformation"]["errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(errors[0]), 200)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Transformation error: " + errors[0]])


class LoggingTests(Checks):
    module = LOGGING
    keys = LOGGING_KEYS

    # --- measured answers -------------------------------------------------------------------------------

    def test_a_sign_in_row_passes_both_keys(self):
        response = self.run_check({"value": [SIGN_IN]})

        self.assertEqual(response["transformedResponse"], {key: True for key in LOGGING_KEYS})
        self.assert_measured(response)
        self.assertEqual(response["additionalInfo"]["transformation"]["inputSummary"], {"logEntryCount": 1})

    def test_the_other_input_shapes_are_read_alike(self):
        body = {"value": [SIGN_IN, SIGN_IN]}
        for label, payload in (
            ("plain", body),
            ("response envelope", {"response": body}),
            ("raw response envelope", {"rawResponse": body}),
            ("enriched", {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}),
            ("json string", json.dumps(body)),
            ("json bytes", json.dumps(body).encode("utf-8")),
        ):
            with self.subTest(shape=label):
                self.assertIs(self.run_check(payload)["transformedResponse"]["isEmailSecurityLoggingEnabled"], True)

    def test_an_empty_sign_in_list_is_not_evaluated(self):
        """An empty list is both a tenant with no retained sign-ins and a read that was not allowed to see them, and
        the read carries no date window that would make it a stated negative, so it proves nothing."""
        for payload in ({"value": []}, {"response": {"value": []}}, {"data": {"value": []}, "validation": PASSED}):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertIn("no sign-ins", response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_entries_that_are_not_sign_in_records_are_not_evaluated(self):
        """Only an object with at least one field is a sign-in entry; a list of anything else proves nothing."""
        for payload in ({"value": [None]}, {"value": [{}]}, {"value": ["x"]}, {"value": [1]}, {"value": [[]]},
                        {"value": [None, {}, "x", 7]}, {"response": {"value": [{}]}}):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertIn("sign-in", response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_a_sign_in_entry_beside_entries_that_cannot_be_read_still_passes(self):
        response = self.run_check({"value": [None, {}, "x", SIGN_IN]})

        self.assertEqual(response["transformedResponse"], {key: True for key in LOGGING_KEYS})
        self.assert_measured(response)

    def test_a_next_link_never_turns_an_empty_page_into_a_fail(self):
        """A page that continues is partial: an empty one is not evidence, and an entry that was seen still proves it."""
        for key in LINK_KEYS:
            for label, wrap in (
                ("top level", lambda body: body),
                ("api response", lambda body: {"apiResponse": body}),
                ("data", lambda body: {"data": body, "validation": PASSED}),
                ("beside the wrapper", lambda body: dict({"response": body}, **{key: NEXT_LINK})),
            ):
                with self.subTest(key=key, shape=label, page="empty"):
                    self.assert_not_evaluated(self.run_check(wrap({"value": [], key: NEXT_LINK})))
                with self.subTest(key=key, shape=label, page="with an entry"):
                    response = self.run_check(wrap({"value": [SIGN_IN], key: NEXT_LINK}))
                    self.assertEqual(response["transformedResponse"], {name: True for name in LOGGING_KEYS})
                    self.assert_measured(response)

    # --- Not evaluated ----------------------------------------------------------------------------------

    def test_a_body_that_is_not_a_sign_in_list_is_not_evaluated(self):
        for payload in (
            {},
            GRAPH_403,
            GRAPH_NONPREMIUM,
            {"value": None},
            {"value": "not a list"},
            {"value": {}},
            {"value": 3},
            {"detail": "Internal Server Error"},
            [],
            [SIGN_IN],
            "[]",
            "3",
            "null",
        ):
            with self.subTest(payload=payload):
                self.assert_not_evaluated(self.run_check(payload))

    def test_malformed_json_is_not_evaluated_with_a_transformation_error(self):
        for payload in ("Service Unavailable", "{not-json", b"\xff\xfe"):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")
                self.assertTrue(response["additionalInfo"]["transformation"]["errors"])

    def test_a_vendor_error_marker_is_not_evaluated(self):
        response = self.run_check({"PSError": "HTTP 403 Forbidden"})

        self.assert_not_evaluated(response)
        self.assertIn("Access denied", response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_failed_input_validation_is_not_evaluated(self):
        response = self.run_check(VALIDATION_FAILED)

        self.assert_not_evaluated(response)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Input validation failed"])

    def test_a_long_exception_message_is_capped(self):
        """The exception text reaches the stored result, so a long one is cut."""
        response = self.run_check(Unreadable())

        self.assert_not_evaluated(response)
        errors = response["additionalInfo"]["transformation"]["errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(errors[0]), 200)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Transformation error: " + errors[0]])


class LicenceTests(Checks):
    module = LICENCE
    keys = LICENCE_KEYS

    # --- measured answers -------------------------------------------------------------------------------

    def test_an_enabled_mailbox_plan_passes(self):
        response = self.run_check({"value": [MAIL_SKU]})

        self.assertEqual(response["transformedResponse"], {"confirmedLicensePurchased": True, "exchangeSkus": ["EXAMPLE_MAIL_PLAN"]})
        self.assert_measured(response)

    def test_the_other_input_shapes_are_read_alike(self):
        body = {"value": [FREE_SKU, MAIL_SKU]}
        for label, payload in (
            ("plain", body),
            ("bare list", body["value"]),
            ("response envelope", {"response": body}),
            ("enriched", {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}),
            ("json string", json.dumps(body)),
            ("json bytes", json.dumps(body).encode("utf-8")),
        ):
            with self.subTest(shape=label):
                self.assertIs(self.run_check(payload)["transformedResponse"]["confirmedLicensePurchased"], True)

    def test_a_list_that_was_read_and_holds_no_enabled_mailbox_plan_is_a_measured_fail(self):
        """The read answered with SKUs and none is an active mailbox: a stated negative, not an unreadable body."""
        for label, rows in (
            ("free SKU only", [FREE_SKU]),
            ("no mail plan at all", [sku("EXAMPLE_OTHER_PLAN", ["EXAMPLE_VIRAL_PLAN"])]),
            ("suspended subscription", [sku("EXAMPLE_MAIL_PLAN", ["EXCHANGE_S_STANDARD"], status="Suspended", enabled=0)]),
            ("deleted subscription", [sku("EXAMPLE_MAIL_PLAN", ["EXCHANGE_S_STANDARD"], status="Deleted", enabled=0)]),
            ("no enabled units", [sku("EXAMPLE_MAIL_PLAN", ["EXCHANGE_S_STANDARD"], enabled=0)]),
            ("mail plan switched off", [sku("EXAMPLE_MAIL_PLAN", ["EXCHANGE_S_STANDARD"], provisioning="Disabled")]),
            ("archive-only plan", [sku("EXAMPLE_ARCHIVE_PLAN", ["EXCHANGE_S_ARCHIVE_ADDON"])]),
        ):
            with self.subTest(case=label):
                response = self.run_check({"value": rows})
                self.assertEqual(response["transformedResponse"]["confirmedLicensePurchased"], False)
                self.assert_measured(response)
                self.assertTrue(response["additionalInfo"]["evaluation"]["failReasons"])

    def test_a_pass_survives_a_row_that_could_not_be_read(self):
        """True needs one enabled mailbox plan that was read; an unreadable row elsewhere cannot undo it."""
        response = self.run_check({"value": [UNREADABLE_ROW, 7, MAIL_SKU]})

        self.assertIs(response["transformedResponse"]["confirmedLicensePurchased"], True)
        self.assert_measured(response)

    def test_an_empty_or_null_next_link_counts_as_complete(self):
        for key in LINK_KEYS:
            for link in (None, ""):
                with self.subTest(key=key, link=link):
                    response = self.run_check({"value": [FREE_SKU], key: link})
                    self.assertEqual(response["transformedResponse"]["confirmedLicensePurchased"], False)
                    self.assert_measured(response)

    def test_a_link_that_is_not_empty_is_partial_whatever_its_type(self):
        """Only null or empty text means the read is complete; any other value is a continuation it did not follow."""
        for key in LINK_KEYS:
            for link in ({}, [], 0, False, 1, True, " ", {"href": NEXT_LINK}, [NEXT_LINK], NEXT_LINK):
                with self.subTest(key=key, link=link):
                    self.assert_not_evaluated(self.run_check({"value": [FREE_SKU], key: link}))
                    self.assertIs(self.run_check({"value": [FREE_SKU, MAIL_SKU], key: link})["transformedResponse"]["confirmedLicensePurchased"], True)

    def test_a_link_beside_rows_three_wrapper_levels_deep_is_found(self):
        body = {"response": {"result": {"apiResponse": {"value": [FREE_SKU], "@odata.nextLink": NEXT_LINK}}}}
        self.assert_not_evaluated(self.run_check(body))

        with_mail = {"response": {"result": {"apiResponse": {"value": [FREE_SKU, MAIL_SKU], "@odata.nextLink": NEXT_LINK}}}}
        self.assertIs(self.run_check(with_mail)["transformedResponse"]["confirmedLicensePurchased"], True)

    def test_a_body_wrapped_four_levels_deep_is_not_evaluated(self):
        """The wrappers are peeled three deep; rows beyond that are unreachable, so the answer is neither True nor False."""
        for rows in ([FREE_SKU], [MAIL_SKU], [FREE_SKU, MAIL_SKU]):
            for link in ({}, {"@odata.nextLink": NEXT_LINK}):
                with self.subTest(rows=len(rows), link=bool(link)):
                    body = {"response": {"result": {"apiResponse": {"Output": dict({"value": rows}, **link)}}}}
                    self.assert_not_evaluated(self.run_check(body))

    def test_a_status_is_read_without_regard_to_case(self):
        for status in ("enabled", "ENABLED", " Enabled "):
            with self.subTest(status=status):
                response = self.run_check({"value": [sku("EXAMPLE_MAIL_PLAN", ["EXCHANGE_S_STANDARD"], status=status)]})
                self.assertIs(response["transformedResponse"]["confirmedLicensePurchased"], True)
                self.assert_measured(response)

    def test_a_status_other_than_enabled_is_inactive_even_with_units(self):
        for status in ("Warning", "Suspended", "Deleted", "LockedOut"):
            with self.subTest(status=status):
                response = self.run_check({"value": [sku("EXAMPLE_MAIL_PLAN", ["EXCHANGE_S_STANDARD"], status=status, enabled=25)]})
                self.assertEqual(response["transformedResponse"]["confirmedLicensePurchased"], False)
                self.assert_measured(response)

    def test_a_sku_whose_status_is_not_enabled_is_a_measured_fail_without_unit_counts(self):
        """The status alone proves the subscription is not active, so the unit count is not needed."""
        row = {"skuPartNumber": "EXAMPLE_MAIL_PLAN", "capabilityStatus": "Suspended",
               "servicePlans": [{"servicePlanName": "EXCHANGE_S_STANDARD", "provisioningStatus": "Success"}]}
        response = self.run_check({"value": [row]})

        self.assertEqual(response["transformedResponse"]["confirmedLicensePurchased"], False)
        self.assert_measured(response)

    # --- Not evaluated ----------------------------------------------------------------------------------

    def test_a_page_that_continues_is_not_a_fail_but_a_seen_mailbox_plan_still_passes(self):
        """A mailbox plan may sit on a page that was not read, so the absence on this page proves nothing."""
        for key in LINK_KEYS:
            for label, wrap in (
                ("top level", lambda body: body),
                ("api response", lambda body: {"apiResponse": body}),
                ("response", lambda body: {"response": body}),
                ("data", lambda body: {"data": body, "validation": PASSED}),
                ("beside the wrapper", lambda body: dict({"response": body}, **{key: NEXT_LINK})),
            ):
                with self.subTest(key=key, shape=label, page="no mailbox plan"):
                    self.assert_not_evaluated(self.run_check(wrap({"value": [FREE_SKU], key: NEXT_LINK})))
                with self.subTest(key=key, shape=label, page="mailbox plan seen"):
                    response = self.run_check(wrap({"value": [FREE_SKU, MAIL_SKU], key: NEXT_LINK}))
                    self.assertIs(response["transformedResponse"]["confirmedLicensePurchased"], True)
                    self.assert_measured(response)

    def test_an_active_looking_sku_with_unreadable_status_or_units_is_not_a_fail(self):
        """The row carries a mailbox plan but its status or unit count cannot be read, so it may be the licence."""
        plans = [{"servicePlanName": "EXCHANGE_S_STANDARD", "provisioningStatus": "Success"}]
        for label, row in (
            ("no status", {"skuPartNumber": "EXAMPLE_MAIL_PLAN", "prepaidUnits": {"enabled": 5}, "servicePlans": plans}),
            ("blank status", {"capabilityStatus": " ", "prepaidUnits": {"enabled": 5}, "servicePlans": plans}),
            ("status is not text", {"capabilityStatus": 1, "prepaidUnits": {"enabled": 5}, "servicePlans": plans}),
            ("no unit counts", {"capabilityStatus": "Enabled", "servicePlans": plans}),
            ("unit counts not an object", {"capabilityStatus": "Enabled", "prepaidUnits": 5, "servicePlans": plans}),
            ("no enabled count", {"capabilityStatus": "Enabled", "prepaidUnits": {"suspended": 0}, "servicePlans": plans}),
            ("null enabled count", {"capabilityStatus": "Enabled", "prepaidUnits": {"enabled": None}, "servicePlans": plans}),
            ("enabled count is text", {"capabilityStatus": "Enabled", "prepaidUnits": {"enabled": "many"}, "servicePlans": plans}),
            ("enabled count is a flag", {"capabilityStatus": "Enabled", "prepaidUnits": {"enabled": True}, "servicePlans": plans}),
        ):
            with self.subTest(case=label):
                self.assert_not_evaluated(self.run_check({"value": [row]}))
                self.assertIs(self.run_check({"value": [row, MAIL_SKU]})["transformedResponse"]["confirmedLicensePurchased"], True)

    def test_a_plan_without_a_name_is_not_a_fail(self):
        """A plan with no name may be the mailbox plan, so it is unreadable, not skipped."""
        for label, plan in (
            ("no name", {"provisioningStatus": "Success"}),
            ("null name", {"servicePlanName": None, "provisioningStatus": "Success"}),
            ("blank name", {"servicePlanName": "  ", "provisioningStatus": "Success"}),
            ("name is not text", {"servicePlanName": 7, "provisioningStatus": "Success"}),
        ):
            with self.subTest(case=label):
                row = sku("EXAMPLE_OTHER_PLAN", ["EXAMPLE_VIRAL_PLAN"])
                row["servicePlans"].append(plan)
                self.assert_not_evaluated(self.run_check({"value": [row]}))
                self.assertIs(self.run_check({"value": [row, MAIL_SKU]})["transformedResponse"]["confirmedLicensePurchased"], True)

    def test_a_body_with_no_sku_rows_is_not_evaluated(self):
        for payload in (
            {"value": []},
            {},
            {"value": None},
            {"value": "not a list"},
            {"value": {}},
            {"value": 3},
            {"@odata.context": "https://graph.example.invalid/v1.0/$metadata#subscribedSkus"},
            [],
            "[]",
            "3",
            "null",
        ):
            with self.subTest(payload=payload):
                self.assert_not_evaluated(self.run_check(payload))

    def test_rows_the_code_cannot_read_are_not_a_fail(self):
        """A row without service plans may be the mailbox plan, so its absence from the answer proves nothing."""
        for payload in (
            {"value": [UNREADABLE_ROW]},
            {"value": [7, "text", None]},
            {"value": [FREE_SKU, UNREADABLE_ROW]},
            {"value": [{"skuPartNumber": "EXAMPLE_ROW", "servicePlans": ["not an object"]}]},
        ):
            with self.subTest(payload=payload):
                self.assert_not_evaluated(self.run_check(payload))

    def test_an_error_body_is_not_evaluated(self):
        for payload in (
            GRAPH_403,
            {"error": "HTTP 403 Forbidden"},
            {"error": True, "statusCode": 503, "message": "unavailable"},
            {"value": [MAIL_SKU], "error": {"code": "Authorization_RequestDenied"}},
        ):
            with self.subTest(payload=payload):
                self.assert_not_evaluated(self.run_check(payload))

    def test_a_vendor_error_marker_is_not_evaluated(self):
        response = self.run_check({"PSError": "HTTP 401 Unauthorized"})

        self.assert_not_evaluated(response)
        self.assertIn("Authentication failed", response["additionalInfo"]["dataCollection"]["errors"][0])

    def test_malformed_json_is_not_evaluated_with_a_transformation_error(self):
        for payload in ("Service Unavailable", "{not-json", b"\xff\xfe"):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")
                self.assertTrue(response["additionalInfo"]["transformation"]["errors"])

    def test_failed_input_validation_is_not_evaluated(self):
        response = self.run_check(VALIDATION_FAILED)

        self.assert_not_evaluated(response)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Input validation failed"])

    def test_a_long_exception_message_is_capped(self):
        """The exception text reaches the stored result, so a long one is cut."""
        response = self.run_check(Unreadable())

        self.assert_not_evaluated(response)
        errors = response["additionalInfo"]["transformation"]["errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(errors[0]), 200)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Transformation error: " + errors[0]])


class NoValueBesideAnError(unittest.TestCase):
    def test_no_not_evaluated_answer_carries_a_value(self):
        """The platform grades a collection error Not evaluated; a False beside it would still be stored as a result."""
        for module, keys in ((DNS, DNS_KEYS), (LOGGING, LOGGING_KEYS), (LICENCE, LICENCE_KEYS)):
            for body in ({}, [], "{bad", GRAPH_403, VALIDATION_FAILED, {"PSError": "HTTP 500"}, Unreadable()):
                with self.subTest(module=module.__name__, body=body):
                    response = module.transform(body)
                    if response["additionalInfo"]["dataCollection"]["status"] == "error":
                        self.assertEqual(response["transformedResponse"], {key: None for key in keys})
                    else:
                        self.fail("an unreadable body must carry a collection error")


if __name__ == "__main__":
    unittest.main()
