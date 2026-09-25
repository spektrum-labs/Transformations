"""
Transformation: openQuarantinedMessagesCount
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: searchPendingRestoreRequests (POST /app/hec-api/v1.0/search/query, office365_emails_email, isRestoreRequested is true, isRestored is false, isRestoreDeclined is false, last 365 days)

Count of quarantined messages awaiting a restore decision: end-user restore requests that are
neither restored nor declined (entityPayload.isRestoreRequested / isRestored / isRestoreDeclined,
API reference, Additional Response Parameters for Email). The count is responseEnvelope.recordsNumber
(total matches; measured on live event queries, where it reads 10000 against a 100-record page), or
the page length when the page is complete. If any returned entity does not match the filter, the
vendor did not apply it and the count is unreadable: None, which fails the check. No live payload
of this method has been captured yet.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "openQuarantinedMessagesCount"

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
                             "method": "searchPendingRestoreRequests"},
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
            return create_response(None, fail_reasons=["No Harmony Email & Collaboration response "
                                   "(responseData) in the input; nothing is proven"],
                                   api_errors=["Unrecognised or error response"])
        err = envelope_error(body)
        if err:
            return create_response(None, fail_reasons=[err], api_errors=[err])
        records = [r for r in body["responseData"] if isinstance(r, dict)]
        def payload(entity):
            p = entity.get("entityPayload")
            if isinstance(p, str):
                try:
                    p = json.loads(p)
                except Exception:
                    p = None
            return p if isinstance(p, dict) else None
        stray = 0
        for e in records:
            p = payload(e)
            if p is None or not flag(p.get("isRestoreRequested")) or flag(p.get("isRestored")) or flag(p.get("isRestoreDeclined")):
                stray = stray + 1
        env = body.get("responseEnvelope") if isinstance(body.get("responseEnvelope"), dict) else {}
        total = None
        raw_total = text(env.get("recordsNumber"))
        if re.match(r"^[0-9]+$", raw_total):
            total = int(raw_total)
        if total is None and not text(env.get("scrollId")):
            total = len(records)
        if total is not None and total < len(records):
            total = len(records)
        summary = {"entitiesOnFirstPage": len(records), "recordsNumber": raw_total,
                   "entitiesNotMatchingFilter": stray, "windowDays": 365}
        if stray:
            return create_response(None, fail_reasons=[str(stray) + " returned entit(y/ies) are not pending restore "
                                   "requests, so the vendor did not apply the filter; the count is unreadable"],
                                   input_summary=summary)
        if total is None:
            return create_response(None, fail_reasons=["The response is paged and carries no recordsNumber; the count "
                                   "is unreadable"], input_summary=summary)
        summary["pendingRestoreRequests"] = total
        if total == 0:
            return create_response(0, pass_reasons=["No quarantined message is awaiting a restore decision"],
                                   input_summary=summary)
        return create_response(total, fail_reasons=[str(total) + " quarantined message(s) have a restore request that "
                               "is neither restored nor declined"], input_summary=summary)
    except Exception as e:
        return create_response(None, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
