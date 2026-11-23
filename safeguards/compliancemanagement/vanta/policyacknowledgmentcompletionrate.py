"""
Transformation: policyAcknowledgmentCompletionRate
Vendor: Vanta (Continuous GRC API). Vanta is a proof source, not a safeguard tool: its answer is third-party
proof (level 3) and Spektrum's own read of the tool (level 4) always wins over it.
Workflow: getVantaPeople (Integration-Service projects the response to the fields this file reads)

Answers what percent of current employees have accepted the policies Vanta assigns them.
The value is 0 to 100, rounded to two decimals: completed / applicable. A person is applicable when Vanta lists them as CURRENT or ON_LEAVE and the task is assigned (a status other than NONE) and not disabled for them. People who are upcoming, inactive or former, exempt people and unassigned tasks are left out and reported.

Not evaluated (None, with a data-collection error) in every case this file cannot judge: an error, empty or
unrecognised body; a read that was not proven complete (the paged read was cut short, or the workflow did
not say); an entry that cannot be read; a status value this file does not know; or no population to measure.
A real zero is told apart from a parse that found nothing: the figures counted over (peopleApplicable, peopleComplete) come back
beside the value, and a body that holds records but yields no readable population is None, never 0.

UNVERIFIED: the field names and status values come from Vanta's published API reference. No real body with
values was available when this was written; the first real read through the integration must be compared with
the counts this file reports before the key is relied on.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "policyAcknowledgmentCompletionRate"
    RESULT_KEY = "vantaPeople"
    LIST_KEY = "people"

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
                             "vendor": "Vanta", "method": "getVantaPeople",
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

    def pick(record, flat, path):
        """A field from the projected record (flat name) or, when the body is unprojected, from the nested
        Vanta shape (dotted path). None when neither holds it."""
        if flat in record:
            return record[flat]
        node = record
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        return node

    POPULATION = ("CURRENT", "ON_LEAVE")
    EMPLOYMENT = ("CURRENT", "ON_LEAVE", "UPCOMING", "INACTIVE", "FORMER")
    TASK = ("COMPLETE", "DUE_SOON", "OVERDUE", "NONE")

    def judge(people, complete):
        """Share of current employees (on leave included) whose policy acknowledgment task is complete, over the people the
        task applies to. Exempt (disabled) and unassigned (NONE) people are left out and reported."""
        counts = {"complete": 0, "open": 0, "exempt": 0, "unassigned": 0, "outOfScope": 0,
                  "unreadable": 0, "unrecognised": 0}
        for person in people:
            if not isinstance(person, dict):
                counts["unreadable"] = counts["unreadable"] + 1
                continue
            employment = up(pick(person, "employmentStatus", "employment.status"))
            if employment is None:
                counts["unreadable"] = counts["unreadable"] + 1
                continue
            if employment not in EMPLOYMENT:
                counts["unrecognised"] = counts["unrecognised"] + 1
                continue
            if employment not in POPULATION:
                counts["outOfScope"] = counts["outOfScope"] + 1
                continue
            if pick(person, "policyDisabledOn", "tasksSummary.details.acceptPolicies.disabled.date") is not None:
                counts["exempt"] = counts["exempt"] + 1
                continue
            status = up(pick(person, "policyStatus", "tasksSummary.details.acceptPolicies.status"))
            if status is None:
                counts["unreadable"] = counts["unreadable"] + 1
            elif status not in TASK:
                counts["unrecognised"] = counts["unrecognised"] + 1
            elif status == "NONE":
                counts["unassigned"] = counts["unassigned"] + 1
            elif status == "COMPLETE":
                counts["complete"] = counts["complete"] + 1
            else:
                counts["open"] = counts["open"] + 1
        applicable = counts["complete"] + counts["open"]
        summary = {"peopleRead": len(people), "peopleApplicable": applicable, "peopleComplete": counts["complete"],
                   "exempt": counts["exempt"], "unassigned": counts["unassigned"],
                   "notCurrentEmployees": counts["outOfScope"], "unreadableEntries": counts["unreadable"],
                   "unrecognisedStatuses": counts["unrecognised"], "readComplete": complete}
        if counts["unreadable"] > 0 or counts["unrecognised"] > 0:
            return not_measured("Entries in the Vanta response could not be read or carry a status this check does "
                                "not know, so the rate would be a guess; nothing is measured.", input_summary=summary)
        if not complete:
            return not_measured("The Vanta read was not proven complete (the paged list was cut short or the "
                                "workflow did not say), so the rate would cover only part of the people; nothing is "
                                "measured.", input_summary=summary)
        if applicable == 0:
            return not_measured("No current employee in the Vanta response has this task assigned, so there is "
                                "nothing to divide by; nothing is measured.", input_summary=summary)
        rate = round(100.0 * counts["complete"] / applicable, 2)
        return create_response(
            rate, extra={"peopleApplicable": applicable, "peopleComplete": counts["complete"]},
            input_summary=summary,
            pass_reasons=[str(counts["complete"]) + " of " + str(applicable) + " current employees have completed "
                          "policy acknowledgment in Vanta (third-party proof, level 3; Spektrum has not read the tool itself)"])


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
