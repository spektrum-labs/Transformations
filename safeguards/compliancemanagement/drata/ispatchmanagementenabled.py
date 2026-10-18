"""
Transformation: isPatchManagementEnabled
Vendor: Drata (GRC API). Drata is a proof source, not a safeguard tool: its answer is third-party
proof (level 3) and Spektrum's own read of the tool (level 4) always wins over it.
Workflow: getDrataTestResults (GET /public/v2/workspaces, then GET .../monitoring-tests for each
workspace; Integration-Service projects each test to id, name, check result, check status and dates)

Answers whether the GRC platform reports its patching tests as passing. It is a claim about patch management, not a read of any endpoint or patch tool.
True when at least one Drata monitoring test is mapped to this criterion, every mapped test is enabled and
passing (checkStatus ENABLED, checkResultStatus PASSED), no mapped test is unclear, and the read is proven
complete (every workspace read, no workspace failed or cut short).
False when any mapped test is enabled and failing (checkStatus ENABLED, checkResultStatus FAILED); a failing
test already seen settles the answer, even if the read was cut short.
Not evaluated (None, with a data-collection error) in every other case: an error, empty or unrecognised
body; a response with no test mapped to this criterion; a mapped test that is not enabled, was not run yet
(READY, PREAUDIT), errored or reports an outcome this file does not know; an entry or a workspace that cannot
be read; a read that was not proven complete (a paged read cut short, a workspace that failed, or the
workflow did not say). It proves nothing, so it is never reported as False.
A test is mapped by words: its name must hold every word of at least one group below, as a whole word (so
"edr" never matches "bedrock").

UNPROVEN AND UNVERIFIED: written from Drata's published API reference only; there is no Drata account to
read. The status values, the response shape and the groups are not checked against a real answer. Review
them against the first real read before this key is relied on.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isPatchManagementEnabled"
    GROUPS = [["patch"], ["patches"], ["patched"], ["unpatched"], ["patching"]]

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
                             "vendor": "Drata", "method": "getDrataTestResults",
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
            return "Drata answered with an error; nothing is measured."
        for field in ("status", "statusCode", "status_code"):
            code = http_status(obj.get(field))
            if code is not None and code >= 400:
                return "Drata answered with an HTTP error; nothing is measured."
        return None

    def workflow_body(data):
        """The getDrataTestResults output is {"drataWorkspaces": {...}, "drataTests": [one entry per
        workspace], "iterateStats": ..., "paginationStats": ...}. Unwrap Integration-Service wrappers
        until that shape is found. Returns (body, error): body is None when the shape is not found;
        error is a fixed reason when a wrapper around the body carries an error marker, in which case
        nothing inside it is trusted."""
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
            if isinstance(data.get("drataTests"), list):
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
        """True when the test's name holds every word of at least one group."""
        held = words(str(test.get("name") or ""))
        for group in GROUPS:
            if all([w in held for w in group]):
                return True
        return False

    def upper_text(value):
        return value.strip().upper() if isinstance(value, str) else ""

    def outcome(test):
        """pass, fail or unknown. Only an enabled test (checkStatus ENABLED) with a result counts:
        PASSED is a pass, FAILED is a fail. A test that is disabled, unused, new or in testing, that was
        not run yet (READY, PREAUDIT), that errored, or whose status is missing or not known is
        unknown: it never reads as a pass and never as a fail."""
        if upper_text(test.get("checkStatus")) != "ENABLED":
            return "unknown"
        result = upper_text(test.get("checkResultStatus"))
        if result == "PASSED":
            return "pass"
        if result == "FAILED":
            return "fail"
        return "unknown"

    def whole(value):
        """A whole number that is not a boolean, else None."""
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value

    def read_complete(body, entries):
        """True only when the workflow proves every workspace was read in full: the workspaces list was
        not cut short, the fan-out processed every workspace with no item error and no cap, and no
        entry carries a truncated mark. A build that does not say is not complete."""
        pstats = body.get("paginationStats")
        wstep = pstats.get("drataWorkspaces") if isinstance(pstats, dict) else None
        if not isinstance(wstep, dict) or wstep.get("paginationTruncated") is not False:
            return False
        workspaces = body.get("drataWorkspaces")
        if not isinstance(workspaces, dict) or workspaces.get("truncated"):
            return False
        wlist = workspaces.get("workspaces")
        if not isinstance(wlist, list):
            return False
        istats = body.get("iterateStats")
        step = istats.get("drataTests") if isinstance(istats, dict) else None
        if not isinstance(step, dict) or step.get("iterateTruncated") is not False:
            return False
        total = whole(step.get("itemsTotal"))
        done = whole(step.get("itemsProcessed"))
        if total is None or done is None or total != done or total != len(entries) or total != len(wlist):
            return False
        if whole(step.get("itemErrors")) != 0:
            return False
        if body.get("paginationTruncated") or body.get("iterateTruncated") or body.get("itemErrors"):
            return False
        for entry in entries:
            if isinstance(entry, dict) and entry.get("truncated"):
                return False
        return True

    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        body, err = workflow_body(input)
        if err:
            return not_measured(err)
        if body is None:
            return not_measured("No readable Drata test results (drataTests) in the input; nothing is measured.")
        entries = body["drataTests"]
        complete = read_complete(body, entries)
        tests = []
        unreadable = 0
        for entry in entries:
            if isinstance(entry, dict) and not entry.get("error") and isinstance(entry.get("tests"), list):
                for test in entry["tests"]:
                    if isinstance(test, dict):
                        tests.append(test)
                    else:
                        unreadable = unreadable + 1
            else:
                unreadable = unreadable + 1
        counts = {"pass": 0, "fail": 0, "unknown": 0}
        matched = []
        for test in tests:
            if mapped(test):
                result = outcome(test)
                counts[result] = counts[result] + 1
                matched.append({"id": str(test.get("id") or "")[:80], "outcome": result})
        summary = {"workspacesRead": len(entries), "testsRead": len(tests), "mappedTests": len(matched),
                   "passing": counts["pass"], "failing": counts["fail"], "unclear": counts["unknown"],
                   "unreadableEntries": unreadable, "readComplete": complete,
                   "matchedTests": matched[:25]}
        if counts["fail"] > 0:
            return create_response(
                False, input_summary=summary,
                fail_reasons=["Drata reports " + str(counts["fail"]) + " enabled test" + ("" if counts["fail"] == 1 else "s") +
                              " for this control as failing"])
        if counts["pass"] == 0 and counts["unknown"] == 0 and unreadable == 0:
            return not_measured("No Drata test in the response is mapped to this control; nothing is measured.",
                                input_summary=summary)
        if counts["unknown"] > 0:
            return not_measured("A Drata test for this control is not enabled, was not run, errored or has an "
                                "outcome that is not recognised, so the control is not proven; nothing is measured.",
                                input_summary=summary)
        if unreadable > 0:
            return not_measured("A workspace or entries in the Drata response could not be read, so a failing "
                                "test may be among them; nothing is measured.", input_summary=summary)
        if not complete:
            return not_measured("The Drata read was not proven complete (a paged read was cut short or the "
                                "workflow did not say), so a failing test may be missing; nothing is measured.",
                                input_summary=summary)
        return create_response(
            True, input_summary=summary,
            pass_reasons=["Drata reports every enabled test mapped to this control as passing (third-party "
                          "proof, level 3; Spektrum has not read the tool itself)"])
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
