"""
Transformation: isLogRetentionConfigured
Vendor: Vanta (Continuous GRC API). Vanta is a proof source, not a safeguard tool: its answer is third-party
proof (level 3) and Spektrum's own read of the tool (level 4) always wins over it.
Workflow: getVantaTestResults (GET /v1/tests, paged; Integration-Service projects each test to
id, name, category, status, dates, the integration keys and the remediation status)

Answers whether server logs are kept for at least 365 days, according to Vanta's own security tests. It is a claim by the GRC platform, not a read of the tool.
True only when at least one mapped Vanta test counts and every mapped test that counts reports OK.
False when any mapped test reports NEEDS_ATTENTION (a failing test already seen settles the answer, even if the
read was cut short).
A mapped test that is NOT_APPLICABLE is left out (Vanta says it does not apply).
A mapped test that is DEACTIVATED (switched off) makes the check Not evaluated, whatever the other tests say, and
the reason names the test id(s): switching a failing test off must not turn the check green. If another mapped test
needs attention the answer is still False (a failure already seen settles it; checked first).
Not evaluated (None, with a data-collection error) in every other case: an error, empty or unrecognised body; no
mapped test present (or all of them not applicable); a mapped test that is IN_PROGRESS, INVALID or reports a status this
file does not know; an entry that cannot be read; a read that was not proven complete (the paged read was cut short,
or the workflow did not say). Not evaluated is never reported as False.

Mapped Vanta test ids (stable ids, matched exactly):
  - logs-retained-for-twelve-months-config

UNVERIFIED beyond one real read: the ids were checked against one real getVantaTestResults read (126 tests); a
company with other connected systems may carry sibling ids that this file does not map.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isLogRetentionConfigured"
    RESULT_KEY = "vantaTests"
    LIST_KEY = "tests"
    # Vanta test ids this check reads. Exact match; ids are Vanta's stable slugs.
    MAPPED_IDS = ("logs-retained-for-twelve-months-config",)
    # Id prefixes: none; ids only
    MAPPED_PREFIXES = ()

    def create_response(value, extra=None, pass_reasons=None, fail_reasons=None, input_summary=None,
                        api_errors=None, transformation_errors=None):
        out = {criteriaKey: value}
        if value is not None and isinstance(extra, dict):
            for name in extra:
                out[name] = extra[name]
        return {
            "transformedResponse": out,
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
        """No verdict: the value is None and dataCollection.status is "error", so the evaluator shows
        Not evaluated instead of a failed check. The reason is fixed text; exception text goes under
        transformation errors only."""
        return create_response(None, fail_reasons=[reason], api_errors=[reason],
                               input_summary=input_summary, transformation_errors=transformation_errors)

    def http_status(value):
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
        """Fixed reason when this one object says the call failed (error, errors, or an HTTP status of
        400 or more), else None. The vendor's own text is never copied."""
        if obj.get("error") or obj.get("errors"):
            return "Vanta answered with an error; nothing is measured."
        for field in ("status", "statusCode", "status_code"):
            code = http_status(obj.get(field))
            if code is not None and code >= 400:
                return "Vanta answered with an HTTP error; nothing is measured."
        return None

    def workflow_body(data):
        """The workflow output is {RESULT_KEY: {LIST_KEY: [...]}, "paginationStats": ...}. Unwrap
        Integration-Service wrappers until that shape is found. Returns (body, error)."""
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
            if isinstance(data.get(RESULT_KEY), dict):
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

    def read_complete(body):
        """True only when the workflow says the paged read was complete: paginationStats for this step
        reports paginationTruncated False and neither the top level nor the projected list carries a
        truncated mark. A build that does not say is not complete."""
        stats = body.get("paginationStats")
        step = stats.get(RESULT_KEY) if isinstance(stats, dict) else None
        if not isinstance(step, dict) or step.get("paginationTruncated") is not False:
            return False
        if body.get("paginationTruncated") or body[RESULT_KEY].get("truncated"):
            return False
        return True

    def up(value):
        """An upper-case, trimmed status, or None when the value is not text."""
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
        return None

    def is_mapped(test_id):
        if test_id in MAPPED_IDS:
            return True
        for prefix in MAPPED_PREFIXES:
            if test_id.startswith(prefix):
                return True
        return False

    COUNTED = ("OK", "NEEDS_ATTENTION")
    LEFT_OUT = ("DEACTIVATED", "NOT_APPLICABLE")
    UNCLEAR = ("IN_PROGRESS", "INVALID")

    def judge(tests, complete):
        """Every mapped test that counts must be OK. A mapped NEEDS_ATTENTION settles False."""
        ok = []
        failing = []
        left_out = []
        deactivated = []
        counts = {"unclear": 0, "unreadable": 0, "unrecognised": 0}
        for test in tests:
            if not isinstance(test, dict):
                counts["unreadable"] = counts["unreadable"] + 1
                continue
            test_id = test.get("id")
            if not isinstance(test_id, str) or not test_id.strip():
                counts["unreadable"] = counts["unreadable"] + 1
                continue
            test_id = test_id.strip()
            if not is_mapped(test_id):
                continue
            status = up(test.get("status"))
            if status is None:
                counts["unreadable"] = counts["unreadable"] + 1
            elif status == "OK":
                ok.append(test_id)
            elif status == "NEEDS_ATTENTION":
                failing.append(test_id)
            elif status == "DEACTIVATED":
                deactivated.append(test_id)
                left_out.append(test_id)
            elif status in LEFT_OUT:
                left_out.append(test_id)
            elif status in UNCLEAR:
                counts["unclear"] = counts["unclear"] + 1
            else:
                counts["unrecognised"] = counts["unrecognised"] + 1
        mapped_counting = len(ok) + len(failing)
        summary = {"testsRead": len(tests), "mappedTestsOk": len(ok), "mappedTestsFailing": len(failing),
                   "mappedTestsLeftOut": len(left_out), "mappedTestsDeactivated": len(deactivated),
                   "mappedTestsUnclear": counts["unclear"],
                   "unreadableEntries": counts["unreadable"], "unrecognisedStatuses": counts["unrecognised"],
                   "readComplete": complete}
        extra = {"mappedTestsOk": len(ok), "mappedTestsFailing": len(failing),
                 "mappedTestsLeftOut": len(left_out)}
        if len(failing) > 0:
            return create_response(
                False, extra=extra, input_summary=summary,
                fail_reasons=[str(len(failing)) + " of " + str(mapped_counting) + " mapped Vanta tests need attention: "
                              + ", ".join(sorted(failing)) + " (third-party proof, level 3)"])
        if len(deactivated) > 0:
            return not_measured("A mapped Vanta test is switched off (DEACTIVATED), so the check cannot be shown to "
                                "hold: " + ", ".join(sorted(deactivated)) + "; nothing is measured.",
                                input_summary=summary)
        if counts["unreadable"] > 0 or counts["unrecognised"] > 0 or counts["unclear"] > 0:
            return not_measured("Entries in the Vanta response could not be read, are still in progress or carry a "
                                "status this check does not know, so the verdict would be a guess; nothing is "
                                "measured.", input_summary=summary)
        if not complete:
            return not_measured("The Vanta read was not proven complete (the paged list was cut short or the "
                                "workflow did not say), so tests may be missing; nothing is measured.",
                                input_summary=summary)
        if mapped_counting == 0:
            return not_measured("No active Vanta test for this check is present in the response (none mapped, or all "
                                "not applicable); nothing is measured.", input_summary=summary)
        return create_response(
            True, extra=extra, input_summary=summary,
            pass_reasons=[str(len(ok)) + " of " + str(mapped_counting) + " mapped Vanta tests report OK (third-party "
                          "proof, level 3; Spektrum has not read the tool itself)"])


    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        body, err = workflow_body(input)
        if err:
            return not_measured(err)
        if body is None:
            return not_measured("No readable Vanta " + LIST_KEY + " (" + RESULT_KEY + ") in the input; nothing is measured.")
        records = body[RESULT_KEY].get(LIST_KEY)
        if not isinstance(records, list):
            return not_measured("The Vanta response holds no " + LIST_KEY + " list; nothing is measured.")
        complete = read_complete(body)
        return judge(records, complete)
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
