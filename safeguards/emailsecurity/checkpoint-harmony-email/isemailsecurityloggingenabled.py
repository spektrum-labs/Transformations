"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: queryOffice365Events (POST /app/hec-api/v1.0/event/query, requestData.saas = [office365_emails], startDate = 30 days ago; all event types)

True when Harmony Email & Collaboration logged at least one security event for the Microsoft 365
mailboxes in the last 30 days (eventId, type, eventCreated present) AND at least one action taken on
an event is logged with its actionType and createTime. Threats detected and actions taken are both
required; a tenant with no logged events or no logged actions reads false.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isEmailSecurityLoggingEnabled"

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
        logged = [r for r in records if text(r.get("eventId")) and text(r.get("type")) and text(r.get("eventCreated"))]
        actions = []
        for r in logged:
            for a in action_list(r):
                if text(a.get("actionType")) and text(a.get("createTime")):
                    actions.append(a)
        types = {}
        for r in logged:
            t = text(r.get("type")).lower()
            types[t] = types.get(t, 0) + 1
        summary = {"recordsOnFirstPage": len(records), "loggedEvents": len(logged),
                   "loggedActions": len(actions), "eventTypes": types, "windowDays": 30}
        if logged and actions:
            summary["newestLoggedEvent"] = max([text(r.get("eventCreated")) for r in logged])
            return create_response(True, pass_reasons=[str(len(logged)) + " security event(s) and " + str(len(actions)) +
                                   " action(s) with actionType and createTime are logged by Harmony Email & Collaboration "
                                   "in the last 30 days (first page of the event query)"], input_summary=summary)
        if not logged:
            return create_response(False, fail_reasons=["No security event with eventId, type and eventCreated was logged "
                                   "for Microsoft 365 mail in the last 30 days"], input_summary=summary)
        return create_response(False, fail_reasons=["Security events are logged but no action taken on them is logged "
                               "(no actions entry with actionType and createTime)"], input_summary=summary)
    except Exception as e:
        return create_response(False, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
