"""
Transformation: isImposterEmailDetectionEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: queryOffice365Events (POST /app/hec-api/v1.0/event/query, requestData.saas = [office365_emails], startDate = 30 days ago; all event types)

True when at least one event in the last 30 days carries a verdict from Check Point's own
anti-phishing engine: the event's data references a security-result entity of type
avanan_ap_scan or checkpoint_ap_scan (the API reference names checkpoint_ap_scan as the ap result
type). Events raised only from Microsoft's verdict (ms_defender_scan) do not count, so a tenant
where Check Point's engine issues no verdicts reads false.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isImposterEmailDetectionEnabled"

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
                             "method": "queryOffice365Events"},
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

    def text(value):
        """Scalar as a trimmed string; the stored raw form writes null as "None"."""
        if value is None:
            return ""
        s = str(value).strip()
        if s.lower() in ("none", "null"):
            return ""
        return s

    def flag(value):
        """HEC booleans arrive as true/false or as the strings "true"/"True"/"false"."""
        if isinstance(value, bool):
            return value
        return text(value).lower() in ("true", "1", "yes")

    def action_list(record):
        acts = record.get("actions")
        if isinstance(acts, str):
            try:
                acts = json.loads(acts)
            except Exception:
                acts = None
        return [a for a in acts if isinstance(a, dict)] if isinstance(acts, list) else []

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
        records = [r for r in body["responseData"] if isinstance(r, dict)]
        engine = re.compile(r"entity_type\W{1,6}(avanan_ap_scan|checkpoint_ap_scan)")
        other = re.compile(r"entity_type\W{1,6}([a-z0-9_]+_scan)")
        ap = []
        seen_other = {}
        for r in records:
            blob = text(r.get("data")) + " " + json.dumps(r.get("additionalData") or "")
            if engine.search(blob):
                ap.append(r)
            else:
                for m in other.findall(blob):
                    seen_other[m] = seen_other.get(m, 0) + 1
        types = {}
        for r in ap:
            t = text(r.get("type")).lower()
            types[t] = types.get(t, 0) + 1
        summary = {"recordsOnFirstPage": len(records), "checkPointApVerdictEvents": len(ap),
                   "checkPointApVerdictTypes": types, "otherScanSources": seen_other, "windowDays": 30}
        if ap:
            return create_response(True, pass_reasons=["Check Point's anti-phishing engine issued verdicts on " +
                                   str(len(ap)) + " message event(s) in the last 30 days (avanan_ap_scan / "
                                   "checkpoint_ap_scan)"], input_summary=summary)
        return create_response(False, fail_reasons=["No event in the last 30 days carries a Check Point anti-phishing "
                               "engine verdict (avanan_ap_scan / checkpoint_ap_scan)"], input_summary=summary)
    except Exception as e:
        return create_response(False, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
