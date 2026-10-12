"""
Transformation: confirmedLicensePurchased
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: getScopes (GET /app/hec-api/v1.0/scopes)

True when the API accepts the key and returns at least one tenant scope (farm:customer).
Not evaluated (None, with a data-collection error) when the body is an error, empty or unrecognised:
it proves nothing, so it is never reported as False. A readable answer that lists nothing keeps the
verdict described above.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

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
                             "method": "getScopes"},
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
        scopes = [s for s in records if isinstance(s, str) and len(s.split(":")) == 2 and s.split(":")[1]]
        summary = {"scopes": len(scopes), "recordsReturned": len(records)}
        if scopes:
            return create_response(True, pass_reasons=["The Harmony Email & Collaboration API accepted this "
                                   "key and returned " + str(len(scopes)) + " tenant scope(s)"], input_summary=summary)
        return create_response(False, fail_reasons=["The scopes call returned no tenant scope: no active "
                               "Harmony Email & Collaboration tenant is evidenced"], input_summary=summary)
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
