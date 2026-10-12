"""
Transformation: isURLReputationBlockListEnforced
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: getAntiPhishingBlockList (GET /app/hec-api/v1.0/exceptions/blacklist)

True when the Harmony Email & Collaboration anti-phishing block list (exceptions of type
Blacklist, API reference 6.1 Get all Exceptions) holds at least one entry that blocks by link
domain (linkDomains non-empty). Entries that match only on sender, subject or attachment do not
count, and an empty block list reads false. This proves an administrator-managed URL block list
is enforced; Check Point's own ThreatCloud URL reputation is not exposed by the API.
The entry shape (stored-raw strings, None written as the string None) is the one measured on the live
getAntiPhishingAllowList read, which the reference documents with the same schema.
Not evaluated (None, with a data-collection error) when the body is an error, empty or unrecognised:
it proves nothing, so it is never reported as False. A readable answer that lists nothing keeps the
verdict described above.
"""

import json
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isURLReputationBlockListEnforced"

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
                             "method": "getAntiPhishingBlockList"},
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
            return not_measured("No readable Harmony Email & Collaboration response (responseData) in the "
                                "input; nothing is measured.")
        err = envelope_error(body)
        if err:
            return not_measured(err)
        records = [r for r in body["responseData"] if isinstance(r, dict)]
        blocking = []
        domains = {}
        for r in records:
            ld = text(r.get("linkDomains"))
            if ld:
                blocking.append(r)
                for d in ld.split(","):
                    d = d.strip().lower()
                    if d:
                        domains[d] = 1
        summary = {"blockListEntries": len(records), "entriesWithLinkDomains": len(blocking),
                   "distinctLinkDomains": len(domains)}
        if blocking:
            return create_response(True, pass_reasons=[str(len(blocking)) + " block-list entr(y/ies) block " +
                                   str(len(domains)) + " link domain(s)"], input_summary=summary)
        if not records:
            return create_response(False, fail_reasons=["The anti-phishing block list is empty"], input_summary=summary)
        return create_response(False, fail_reasons=["None of the " + str(len(records)) + " block-list entr(y/ies) "
                               "blocks by link domain (linkDomains empty)"], input_summary=summary)
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
