"""
Transformation: messageMoveAuditTrailEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: queryOffice365Events (POST /app/hec-api/v1.0/event/query, requestData.saas = [office365_emails], startDate = 30 days ago; all event types)

True when at least one message-move action (quarantine, restore, delete, move) appears in the event
log for the last 30 days and EVERY such action on the page carries actionType, createTime and
relatedEntityId, i.e. an auditable who-what-when trail. No move action observed, or any move action
missing a field, reads false. Judges the first page of the event query (the oldest events of the
window); the response carries no audit-log endpoint beyond this.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "messageMoveAuditTrailEnabled"

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
        words = ("quarantine", "restore", "delete", "move")
        moves = []
        for r in records:
            for a in action_list(r):
                at = text(a.get("actionType")).lower()
                for w in words:
                    if w in at:
                        moves.append(a)
                        break
        incomplete = [a for a in moves if not (text(a.get("createTime")) and text(a.get("relatedEntityId")))]
        kinds = {}
        for a in moves:
            k = text(a.get("actionType")).lower()
            kinds[k] = kinds.get(k, 0) + 1
        summary = {"recordsOnFirstPage": len(records), "moveActions": len(moves),
                   "moveActionsMissingAuditFields": len(incomplete), "moveActionTypes": kinds, "windowDays": 30}
        if not moves:
            return create_response(False, fail_reasons=["No quarantine, restore, delete or move action appears in the "
                                   "event log for the last 30 days, so no audit trail is evidenced"], input_summary=summary)
        if incomplete:
            return create_response(False, fail_reasons=[str(len(incomplete)) + " of " + str(len(moves)) + " message-move "
                                   "action(s) lack createTime or relatedEntityId, so the trail is not auditable"],
                                   input_summary=summary)
        return create_response(True, pass_reasons=["All " + str(len(moves)) + " message-move action(s) in the event log "
                               "carry actionType, createTime and relatedEntityId"], input_summary=summary)
    except Exception as e:
        return create_response(False, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
