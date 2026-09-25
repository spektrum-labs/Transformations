"""
Transformation: unverifiedAllowPolicyCount
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: getAntiPhishingAllowList (GET /app/hec-api/v1.0/exceptions/whitelist)

Count of anti-phishing allow-list (whitelist) exceptions. The API has no review field, so every entry counts. Unreadable input returns None, which fails the check.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "unverifiedAllowPolicyCount"

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
                             "method": "getAntiPhishingAllowList"},
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
            return create_response(None, fail_reasons=["No Harmony Email & Collaboration response "
                                   "(responseData) in the input; nothing is proven"],
                                   api_errors=["Unrecognised or error response"])
        err = envelope_error(body)
        if err:
            return create_response(None, fail_reasons=[err], api_errors=[err])
        records = body["responseData"]
        entries = [r for r in records if isinstance(r, dict)]
        summary = {"allowListEntries": len(entries)}
        if entries:
            return create_response(len(entries), fail_reasons=[str(len(entries)) + " anti-phishing allow-list "
                                   "(whitelist) exception(s) bypass inspection; the API carries no review or "
                                   "verification field, so each one counts as unverified"], input_summary=summary)
        return create_response(0, pass_reasons=["No anti-phishing allow-list (whitelist) exception is configured"],
                               input_summary=summary)
    except Exception as e:
        return create_response(None, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
