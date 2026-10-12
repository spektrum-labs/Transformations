"""
Transformation: isAccountTakeoverDetectionEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: queryAnomalyEvents (POST /app/hec-api/v1.0/event/query (requestData.startDate = 30 days ago))

True when at least one security event matching type in ("anomaly",) was raised in the last 30 days. Evidence of the engine working, not a read of the policy toggle; a quiet tenant reads false.
Not evaluated (None, with a data-collection error) when the body is an error, empty or unrecognised:
it proves nothing, so it is never reported as False. A readable answer that lists nothing keeps the
verdict described above.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isAccountTakeoverDetectionEnabled"

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
                             "vendor": "Check Point Harmony Email & Collaboration",
                             "method": "queryAnomalyEvents"},
            },
        }

    def not_measured(reason, transformation_errors=None):
        """No verdict: the value is None and dataCollection.status is "error", so the evaluator
        shows Not evaluated instead of a failed check. The reason is fixed text; exception text
        goes under transformation errors only."""
        return create_response(None, fail_reasons=[reason], api_errors=[reason],
                               transformation_errors=transformation_errors)

    def hec_body(data):
        """The HEC API answers {"responseEnvelope": {...}, "responseData": [...]}. Unwrap
        Integration-Service wrappers until that shape is found; anything else is None."""
        for attempt in range(4):
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    return None
            if not isinstance(data, dict):
                return None
            if isinstance(data.get("responseData"), list):
                return data
            nxt = None
            for key in ("apiResponse", "response", "result", "data", "rawResponse"):
                if isinstance(data.get(key), (dict, str)):
                    nxt = data[key]
                    break
            if nxt is None:
                return None
            data = nxt
        return None

    def envelope_error(body):
        """Fixed reason when the response says the call failed, else None. The vendor's own
        response text is never copied into the reason."""
        env = body.get("responseEnvelope")
        if isinstance(env, dict):
            code = env.get("responseCode")
            if code is not None and str(code) not in ("200", "0"):
                return "Harmony Email & Collaboration answered with an error status; nothing is measured."
        if body.get("error") or body.get("errors"):
            return "Harmony Email & Collaboration answered with an error; nothing is measured."
        for field in ("statusCode", "status_code"):
            status = body.get(field)
            if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
                return "Harmony Email & Collaboration answered with an HTTP error; nothing is measured."
        return None

    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        body = hec_body(input)
        if body is None:
            return not_measured("No readable Harmony Email & Collaboration response (responseData) in the "
                                "input; nothing is measured.")
        err = envelope_error(body)
        if err:
            return not_measured(err)
        records = body["responseData"]
        wanted = ("anomaly",)
        field = "type"
        matched = [r for r in records if isinstance(r, dict) and str(r.get(field) or "").lower() in wanted]
        summary = {"recordsOnFirstPage": len(records), "matchingEvents": len(matched),
                   "matchedOn": field + " in " + ", ".join(sorted(wanted)), "windowDays": 30}
        if matched:
            newest = max([str(r.get("eventCreated") or "") for r in matched])
            summary["newestMatchingEvent"] = newest
            return create_response(True, pass_reasons=["Harmony Email & Collaboration raised anomaly (suspicious login / account compromise) events in the last 30 days"], input_summary=summary)
        return create_response(False, fail_reasons=["No anomaly event in the last 30 days: account-takeover detection is not evidenced"], input_summary=summary)
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
