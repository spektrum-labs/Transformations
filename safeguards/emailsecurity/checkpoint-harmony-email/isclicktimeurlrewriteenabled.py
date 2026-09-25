"""
Transformation: isClickTimeURLRewriteEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: searchLinkEmails (POST /app/hec-api/v1.0/search/query, office365_emails_email, entityPayload.emailLinks isNotEmpty, last 7 days)

True when at least one email entity that contains links (entityPayload.emailLinks non-empty)
carries a click-time protection result: entitySecurityResults.combinedVerdict.clicktimeProtection
is set, or entitySecurityResults.clicktimeProtection is a non-empty result with a verdict (API
reference, Get the Details of a Specific Entity: combinedVerdict.clicktimeProtection = Clicktime
protection verdict). Links are only scanned at click time when HEC rewrites them, so a verdict is
the observable effect of URL rewriting. Entities without links are ignored (the filter is not
trusted); no linked email in the window, or none with a verdict, reads false. Field names are
from the API reference; no live payload of this method has been captured yet.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isClickTimeURLRewriteEnabled"

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
                             "method": "searchLinkEmails"},
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
        def as_obj(value):
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except Exception:
                    return None
            return value
        def has_links(entity):
            p = as_obj(entity.get("entityPayload"))
            if not isinstance(p, dict):
                return False
            links = as_obj(p.get("emailLinks"))
            return isinstance(links, list) and len([l for l in links if text(l)]) > 0
        def ctp_verdict(entity):
            sr = as_obj(entity.get("entitySecurityResults"))
            if not isinstance(sr, dict):
                return ""
            cv = sr.get("combinedVerdict")
            if isinstance(cv, dict) and text(cv.get("clicktimeProtection")):
                return text(cv.get("clicktimeProtection"))
            ctp = sr.get("clicktimeProtection")
            if isinstance(ctp, dict):
                ctp = [ctp]
            if isinstance(ctp, list):
                for item in ctp:
                    if isinstance(item, dict) and (text(item.get("verdict")) or text(item.get("statusCode"))):
                        return text(item.get("verdict")) or text(item.get("statusCode"))
            return ""
        linked = [r for r in records if has_links(r)]
        scanned = 0
        verdicts = {}
        for e in linked:
            v = ctp_verdict(e)
            if v:
                scanned = scanned + 1
                verdicts[v.lower()] = verdicts.get(v.lower(), 0) + 1
        summary = {"entitiesOnFirstPage": len(records), "entitiesWithLinks": len(linked),
                   "entitiesWithClicktimeVerdict": scanned, "clicktimeVerdicts": verdicts, "windowDays": 7}
        if scanned:
            return create_response(True, pass_reasons=[str(scanned) + " of " + str(len(linked)) + " email(s) with links "
                                   "carry a click-time protection verdict"], input_summary=summary)
        if not linked:
            return create_response(False, fail_reasons=["The entity search returned no email with links in the last "
                                   "7 days, so click-time URL protection is not evidenced"], input_summary=summary)
        return create_response(False, fail_reasons=["None of the " + str(len(linked)) + " email(s) with links carries a "
                               "click-time protection verdict (links are not being rewritten and scanned)"],
                               input_summary=summary)
    except Exception as e:
        return create_response(False, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
