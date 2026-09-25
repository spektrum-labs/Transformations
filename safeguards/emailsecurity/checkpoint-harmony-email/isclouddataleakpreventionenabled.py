"""
Transformation: isCloudDataLeakPreventionEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: queryDlpEvents (POST /app/hec-api/v1.0/event/query (requestData.startDate = 30 days ago))

True when at least one security event matching type in ("dlp",) was raised in the last 30 days. Evidence of the engine working, not a read of the policy toggle; a quiet tenant reads false.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isCloudDataLeakPreventionEnabled"

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
                             "method": "queryDlpEvents"},
            },
        }

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
        env = body.get("responseEnvelope")
        if isinstance(env, dict):
            code = env.get("responseCode")
            if code is not None and str(code) not in ("200", "0"):
                return "HEC responseCode " + str(code) + ": " + str(env.get("responseText") or "")
        return None

    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        body = hec_body(input)
        if body is None:
            return create_response(False, fail_reasons=["No Harmony Email & Collaboration response "
                                   "(responseData) in the input; nothing is proven"],
                                   api_errors=["Unrecognised or error response"])
        err = envelope_error(body)
        if err:
            return create_response(False, fail_reasons=[err], api_errors=[err])
        records = body["responseData"]
        wanted = ("dlp",)
        field = "type"
        matched = [r for r in records if isinstance(r, dict) and str(r.get(field) or "").lower() in wanted]
        summary = {"recordsOnFirstPage": len(records), "matchingEvents": len(matched),
                   "matchedOn": field + " in " + ", ".join(sorted(wanted)), "windowDays": 30}
        if matched:
            newest = max([str(r.get("eventCreated") or "") for r in matched])
            summary["newestMatchingEvent"] = newest
            return create_response(True, pass_reasons=["Harmony Email & Collaboration raised DLP events in the last 30 days, so a DLP policy is inspecting content"], input_summary=summary)
        return create_response(False, fail_reasons=["No DLP event in the last 30 days: data leak prevention is not evidenced"], input_summary=summary)
    except Exception as e:
        return create_response(False, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
