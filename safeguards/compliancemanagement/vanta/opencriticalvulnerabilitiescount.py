"""
Transformation: openCriticalVulnerabilitiesCount
Vendor: Vanta (Continuous GRC API). Vanta is a proof source, not a safeguard tool: its answer is third-party
proof (level 3) and Spektrum's own read of the tool (level 4) always wins over it.
Workflow: getVantaVulnerabilities, two reads in one run: vantaVulnerabilities (GET /v1/vulnerabilities?isDeactivated=false,
paged; each vulnerability projected to id, severity, the remediate-by date and the first-detected date) and vantaTests
(GET /v1/tests, paged; read here only for the test vulnerability-scanner-linked-to-vanta)

Answers how many vulnerabilities Vanta lists as open with severity CRITICAL. 0 is the secure state.

Vanta lists the vulnerabilities its connected scanners currently report; a fixed vulnerability leaves the list.
The read asks Vanta for active vulnerabilities only (isDeactivated=false), so a vulnerability a person deactivated
in Vanta is not counted; every listed entry is treated as open.

A count of zero is reported only when the vulnerability read succeeded and was not cut short AND the Vanta test
vulnerability-scanner-linked-to-vanta has status exactly OK in the tests read. An empty list alone is not evidence
of no vulnerabilities (a company with no scanner connected also gets an empty list).

Not evaluated (None, with a data-collection error) in every case this file cannot judge: an error, empty or
unrecognised body; a read that was not proven complete (the paged read was cut short, or the workflow did not
say), whatever the count; an entry that cannot be read; a severity this file does not know (a null or unrecognised severity on any entry); or a count of zero without the scanner test
being OK (missing from the response, or any status other than OK).

UNVERIFIED (doc-verified, not live-verified): the field names (severity, remediateByDate) come from Vanta's
published API reference (developer.vanta.com/reference/listvulnerabilities). The first real read returned no
vulnerabilities, so no body with values has been compared with the counts this file reports.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "openCriticalVulnerabilitiesCount"
    RESULT_KEY = "vantaVulnerabilities"
    LIST_KEY = "vulnerabilities"

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
                             "vendor": "Vanta", "method": "getVantaVulnerabilities",
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

    SCANNER_TEST_ID = "vulnerability-scanner-linked-to-vanta"

    def scanner_state(body):
        """"ok" when the Vanta test that says a vulnerability scanner is linked has status exactly OK in the
        tests read that rides with this workflow; "not_ok" when it has any other status; "missing" when the
        tests read, the list or the test itself is absent."""
        block = body.get("vantaTests")
        listed = block.get("tests") if isinstance(block, dict) else None
        if not isinstance(listed, list):
            return "missing"
        for entry in listed:
            if isinstance(entry, dict) and entry.get("id") == SCANNER_TEST_ID:
                return "ok" if entry.get("status") == "OK" else "not_ok"
        return "missing"

    def zero_guard(scanner):
        """None when a count of zero may be reported, else the reason it may not. An empty list or a clean list
        is only evidence of no findings when Vanta itself says a scanner is linked."""
        if scanner == "ok":
            return None
        if scanner == "not_ok":
            return ("The Vanta test for a linked vulnerability scanner is not OK, so a count of zero is not "
                    "evidence of no vulnerabilities; nothing is measured.")
        return ("The Vanta test for a linked vulnerability scanner was not in the response, so a count of zero is "
                "not evidence of no vulnerabilities; nothing is measured.")

    def up(value):
        """An upper-case, trimmed status, or None when the value is not text."""
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
        return None

    SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def judge(items, complete, scanner):
        """Count of listed vulnerabilities whose severity is CRITICAL."""
        counts = {"critical": 0, "unreadable": 0, "unrecognised": 0}
        for item in items:
            if not isinstance(item, dict):
                counts["unreadable"] = counts["unreadable"] + 1
                continue
            severity = up(item.get("severity"))
            if severity is None:
                counts["unreadable"] = counts["unreadable"] + 1
            elif severity not in SEVERITIES:
                counts["unrecognised"] = counts["unrecognised"] + 1
            elif severity == "CRITICAL":
                counts["critical"] = counts["critical"] + 1
        summary = {"vulnerabilitiesRead": len(items), "openCritical": counts["critical"],
                   "unreadableEntries": counts["unreadable"], "unrecognisedSeverities": counts["unrecognised"],
                   "readComplete": complete}
        if counts["unreadable"] > 0 or counts["unrecognised"] > 0:
            return not_measured("Entries in the Vanta response could not be read or carry a severity this check does "
                                "not know, so the count would be a guess; nothing is measured.", input_summary=summary)
        if not complete:
            return not_measured("The Vanta read was not proven complete (the paged list was cut short or the "
                                "workflow did not say), so vulnerabilities may be missing from the count; nothing is "
                                "measured.", input_summary=summary)
        if counts["critical"] == 0:
            zero_error = zero_guard(scanner)
            if zero_error:
                return not_measured(zero_error, input_summary=summary)
        return create_response(
            counts["critical"], extra={"vulnerabilitiesRead": len(items)}, input_summary=summary,
            pass_reasons=[str(counts["critical"]) + " of " + str(len(items)) + " open vulnerabilities in Vanta are "
                          "critical (third-party proof, level 3)"])


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
        return judge(records, complete, scanner_state(body))
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
