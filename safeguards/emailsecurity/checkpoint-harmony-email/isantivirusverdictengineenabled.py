"""
Transformation: isAntivirusVerdictEngineEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: searchAttachmentEmails (POST /app/hec-api/v1.0/search/query, office365_emails_email, attachmentCount > 0, last 7 days)

True when at least one email entity with attachments returned by the entity search carries an
antivirus result: entitySecurityResults.av is a non-empty list with a verdict, or
entitySecurityResults.combinedVerdict.av is set (API reference, Get the Details of a Specific
Entity: combinedVerdict.av = Antivirus verdict). Entities without an av result, or no entity with
attachments in the window, read false. Field names are from the API reference; no live payload of
this method has been captured yet.
Fails closed: an empty, error or unrecognised body proves nothing.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isAntivirusVerdictEngineEnabled"

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
                             "method": "searchAttachmentEmails"},
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
        def av_verdict(entity):
            sr = entity.get("entitySecurityResults")
            if isinstance(sr, str):
                try:
                    sr = json.loads(sr)
                except Exception:
                    sr = None
            if not isinstance(sr, dict):
                return ""
            av = sr.get("av")
            if isinstance(av, dict):
                av = [av]
            if isinstance(av, list):
                for item in av:
                    if isinstance(item, dict) and (text(item.get("verdict")) or text(item.get("statusCode"))):
                        return text(item.get("verdict")) or text(item.get("statusCode"))
            cv = sr.get("combinedVerdict")
            if isinstance(cv, dict) and text(cv.get("av")):
                return text(cv.get("av"))
            return ""
        entities = [r for r in records if isinstance(r.get("entityInfo"), dict) or isinstance(r.get("entitySecurityResults"), dict)]
        scanned = []
        verdicts = {}
        for e in entities:
            v = av_verdict(e)
            if v:
                scanned.append(e)
                verdicts[v.lower()] = verdicts.get(v.lower(), 0) + 1
        summary = {"entitiesOnFirstPage": len(entities), "entitiesWithAvVerdict": len(scanned),
                   "avVerdicts": verdicts, "windowDays": 7}
        if scanned:
            return create_response(True, pass_reasons=[str(len(scanned)) + " of " + str(len(entities)) + " email(s) with "
                                   "attachments carry a Check Point antivirus verdict (entitySecurityResults.av)"],
                                   input_summary=summary)
        if not entities:
            return create_response(False, fail_reasons=["The entity search returned no email with attachments in the "
                                   "last 7 days, so the antivirus engine's verdicts are not evidenced"], input_summary=summary)
        return create_response(False, fail_reasons=["None of the " + str(len(entities)) + " email(s) with attachments "
                               "carries an antivirus verdict (entitySecurityResults.av empty)"], input_summary=summary)
    except Exception as e:
        return create_response(False, fail_reasons=["Transformation error"],
                               transformation_errors=[str(e)])
