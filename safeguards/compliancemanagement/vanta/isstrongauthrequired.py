"""
Transformation: isStrongAuthRequired
Vendor: Vanta (Continuous GRC API). Vanta is a proof source, not a safeguard tool: its answer is
third-party proof (level 3) and Spektrum's own read of the tool (level 4) always wins over it.
Workflow: getVantaTestResults (GET /v1/tests, paged; Integration-Service projects each test to
id, name, status and dates)

Answers whether the GRC platform reports its multi-factor authentication tests as passing. It is a claim about MFA, not a read of any identity provider.
True when at least one Vanta test is mapped to this criterion, every mapped test reports OK, no mapped
test is unclear, and the read is proven complete.
False when any mapped test reports NEEDS_ATTENTION (a failing test already seen settles the answer, even
if the read was cut short).
Not evaluated (None, with a data-collection error) in every other case: an error, empty or unrecognised
body; a response with no test mapped to this criterion; a mapped test that is DEACTIVATED, IN_PROGRESS,
INVALID or reports an outcome this file does not know; an entry that cannot be read; a read that was not
proven complete (the paged read was cut short, or the workflow did not say). It proves nothing, so it is
never reported as False. A test marked NOT_APPLICABLE is left out of the answer: Vanta says the control
does not apply to the company.
A test is mapped by words: its id or name must hold every word of at least one group below, as a whole
word (so "edr" never matches "bedrock").

UNVERIFIED: the groups come from Vanta's published API reference and its documented test-id style (slugs
such as aws-account-access-removed-on-termination). No Vanta account was read while writing this. Review
the mapped ids against the first real read before this key is relied on.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isStrongAuthRequired"
    GROUPS = [["mfa"], ["2fa"], ["multifactor"], ["multi", "factor"], ["two", "factor"]]

    def create_response(value, pass_reasons=None, fail_reasons=None, input_summary=None,
                        api_errors=None, transformation_errors=None):
        return {
            "transformedResponse": {criteriaKey: value},
            "additionalInfo": {
                "dataCollection": {"status": "error" if api_errors else "success",
                                   "errors": api_errors or []},
                "validation": {"status": "unknown", "errors": [], "warnings": []},
                "transformation": {"status": "error" if transformation_errors else "success",
                                   "errors": transformation_errors or [],
                                   "inputSummary": input_summary or {}},
                "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                               "recommendations": [], "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z",
                             "schemaVersion": "1.0", "transformationId": criteriaKey,
                             "vendor": "Vanta", "method": "getVantaTestResults",
                             "proofSource": "third_party_claim", "proofLevel": 3},
            },
        }

    def not_measured(reason, input_summary=None, transformation_errors=None):
        """No verdict: the value is None and dataCollection.status is "error", so the evaluator
        shows Not evaluated instead of a failed check. The reason is fixed text; exception text
        goes under transformation errors only."""
        return create_response(None, fail_reasons=[reason], api_errors=[reason],
                               input_summary=input_summary, transformation_errors=transformation_errors)

    def http_status(value):
        """An HTTP status as a number: a number, or text such as "401". Booleans, blank or
        non-numeric text and any other type are None, which is not an error."""
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            digits = value.strip()
            if digits.isascii() and digits.isdigit():
                return int(digits)
        return None

    def marker_error(obj):
        """Fixed reason when this one object says the call failed (error, errors, or an HTTP
        status of 400 or more), else None. The vendor's own text is never copied."""
        if obj.get("error") or obj.get("errors"):
            return "Vanta answered with an error; nothing is measured."
        for field in ("status", "statusCode", "status_code"):
            code = http_status(obj.get(field))
            if code is not None and code >= 400:
                return "Vanta answered with an HTTP error; nothing is measured."
        return None

    def workflow_body(data):
        """The getVantaTestResults output is {"vantaTests": {"tests": [...]}, "paginationStats": ...}.
        Unwrap Integration-Service wrappers until that shape is found. Returns (body, error): body
        is None when the shape is not found; error is a fixed reason when a wrapper around the body
        carries an error marker, in which case nothing inside it is trusted."""
        for attempt in range(4):
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    return None, None
            if not isinstance(data, dict):
                return None, None
            err = marker_error(data)
            if err:
                return None, err
            if isinstance(data.get("vantaTests"), dict):
                return data, None
            nxt = None
            for key in ("apiResponse", "response", "result", "data", "rawResponse"):
                if isinstance(data.get(key), (dict, str)):
                    nxt = data[key]
                    break
            if nxt is None:
                return None, None
            data = nxt
        return None, None

    def words(text):
        """Lower-case ASCII words of a text: letters and digits, everything else separates."""
        found = []
        current = ""
        for ch in str(text).lower():
            if ch.isascii() and ch.isalnum():
                current = current + ch
            else:
                if current:
                    found.append(current)
                current = ""
        if current:
            found.append(current)
        return found

    def mapped(test):
        """True when the test's id or name holds every word of at least one group."""
        held = words(str(test.get("id") or "") + " " + str(test.get("name") or ""))
        for group in GROUPS:
            if all([w in held for w in group]):
                return True
        return False

    def outcome(test):
        """pass, fail, skip or unknown, from Vanta's status. Only OK is a pass and only NEEDS_ATTENTION
        is a fail. NOT_APPLICABLE is left out. DEACTIVATED, IN_PROGRESS, INVALID, a missing status and
        any status this file does not know are unknown: they never read as a pass and never as a fail."""
        status = test.get("status")
        if not isinstance(status, str):
            return "unknown"
        status = status.strip().upper()
        if status == "OK":
            return "pass"
        if status == "NEEDS_ATTENTION":
            return "fail"
        if status == "NOT_APPLICABLE":
            return "skip"
        return "unknown"

    def read_complete(body):
        """True only when the workflow says the paged read was complete: paginationStats for the
        tests step reports paginationTruncated False, and neither the top level nor the projected
        tests carry a truncated mark. A build that does not say is not complete."""
        stats = body.get("paginationStats")
        step = stats.get("vantaTests") if isinstance(stats, dict) else None
        if not isinstance(step, dict) or step.get("paginationTruncated") is not False:
            return False
        if body.get("paginationTruncated") or body["vantaTests"].get("truncated"):
            return False
        return True

    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        body, err = workflow_body(input)
        if err:
            return not_measured(err)
        if body is None:
            return not_measured("No readable Vanta test results (vantaTests) in the input; nothing is measured.")
        tests = body["vantaTests"].get("tests")
        if not isinstance(tests, list):
            return not_measured("The Vanta response holds no test list; nothing is measured.")
        complete = read_complete(body)
        unreadable = len([t for t in tests if not isinstance(t, dict)])
        counts = {"pass": 0, "fail": 0, "skip": 0, "unknown": 0}
        matched = []
        for test in tests:
            if isinstance(test, dict) and mapped(test):
                result = outcome(test)
                counts[result] = counts[result] + 1
                matched.append({"id": str(test.get("id") or "")[:80], "outcome": result})
        summary = {"testsRead": len(tests), "mappedTests": len(matched), "passing": counts["pass"],
                   "failing": counts["fail"], "notApplicable": counts["skip"], "unclear": counts["unknown"],
                   "unreadableEntries": unreadable, "readComplete": complete,
                   "matchedTests": matched[:25]}
        if counts["fail"] > 0:
            return create_response(
                False, input_summary=summary,
                fail_reasons=["Vanta reports " + str(counts["fail"]) + " test" + ("" if counts["fail"] == 1 else "s") +
                              " for this control as needing attention"])
        if counts["pass"] == 0 and counts["unknown"] == 0 and unreadable == 0:
            return not_measured("No Vanta test in the response is mapped to this control, or every mapped test "
                                "is not applicable; nothing is measured.", input_summary=summary)
        if counts["unknown"] > 0:
            return not_measured("A Vanta test for this control is deactivated, in progress, invalid or has an "
                                "outcome that is not recognised, so the control is not proven; nothing is measured.",
                                input_summary=summary)
        if unreadable > 0:
            return not_measured("Entries in the Vanta response could not be read, so a failing test may be "
                                "among them; nothing is measured.", input_summary=summary)
        if not complete:
            return not_measured("The Vanta read was not proven complete (the paged list was cut short or the "
                                "workflow did not say), so a failing test may be missing; nothing is measured.",
                                input_summary=summary)
        return create_response(
            True, input_summary=summary,
            pass_reasons=["Vanta reports every test mapped to this control as passing (third-party proof, "
                          "level 3; Spektrum has not read the tool itself)"])
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
