"""
Transformation: isPostDeliveryQuarantineEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: queryOffice365Events (POST /app/hec-api/v1.0/event/query, requestData.saas = [office365_emails], startDate = 30 days ago; all event types)

True when Harmony Email & Collaboration executed at least one quarantine action on a Microsoft 365
mailbox message in the last 30 days (an event whose actions include an actionType containing
'quarantine' with a createTime). HEC acts on mailbox messages through the Microsoft API, so an
executed quarantine shows retroactive quarantine is working; it does not separate pre- from
post-delivery verdicts. A quiet tenant, or one that only tags or alerts, reads false.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isPostDeliveryQuarantineEnabled"

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
        hits = []
        for r in records:
            for a in action_list(r):
                if "quarantine" in text(a.get("actionType")).lower() and text(a.get("createTime")):
                    hits.append((r, a))
                    break
        summary = {"recordsOnFirstPage": len(records), "eventsWithQuarantineAction": len(hits), "windowDays": 30}
        if hits:
            summary["newestQuarantineAction"] = max([text(a.get("createTime")) for r, a in hits])
            summary["quarantinedEventTypes"] = sorted(list(set([text(r.get("type")).lower() for r, a in hits])))
            return create_response(True, pass_reasons=["Harmony Email & Collaboration quarantined " + str(len(hits)) +
                                   " Microsoft 365 message(s) in the last 30 days (quarantine action with createTime)"],
                                   input_summary=summary)
        return create_response(False, fail_reasons=["No executed quarantine action on a Microsoft 365 message in the "
                               "last 30 days; retroactive quarantine is not evidenced"], input_summary=summary)
    except Exception as e:
        return create_response(False, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
