"""
Transformation: isImposterEmailDetectionEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: queryOffice365Events (POST /app/hec-api/v1.0/event/query, requestData.saas = [office365_emails], startDate = 30 days ago; all event types)

True when at least one event in the last 30 days carries a verdict from Check Point's own
anti-phishing engine: the event's data references a security-result entity of type
avanan_ap_scan or checkpoint_ap_scan (the API reference names checkpoint_ap_scan as the ap result
type). Events raised only from Microsoft's verdict (ms_defender_scan) do not count, so a tenant
where Check Point's engine issues no verdicts reads false.
Not evaluated (None, with a data-collection error) when the body is an error, empty or unrecognised:
it proves nothing, so it is never reported as False. A readable answer that lists nothing keeps the
verdict described above.
One page of a paged answer is not the whole window: when the response carries a scrollId or a
recordsNumber above the page, a match already seen still counts, but an absence is not proven, so a
page with no match reads None (Not evaluated) and never False.
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

    def not_measured(reason, transformation_errors=None):
        """No verdict: the value is None and dataCollection.status is "error", so the evaluator
        shows Not evaluated instead of a failed check. The reason is fixed text; exception text
        goes under transformation errors only."""
        return create_response(None, fail_reasons=[reason], api_errors=[reason],
                               transformation_errors=transformation_errors)

    def http_status(value):
        """An HTTP status as a number: a number, or text such as "401" or " 403 ". Booleans, blank
        or non-numeric text and any other type are None, which is not an error."""
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            digits = value.strip()
            if digits.isascii() and digits.isdigit():
                return int(digits)
        return None

    def marker_error(obj):
        """Fixed reason when this one object says the call failed (error, errors, or an HTTP
        status of 400 or more in status, statusCode or status_code), else None. The vendor's own
        response text is never copied into the reason."""
        if obj.get("error") or obj.get("errors"):
            return "Harmony Email & Collaboration answered with an error; nothing is measured."
        for field in ("status", "statusCode", "status_code"):
            code = http_status(obj.get(field))
            if code is not None and code >= 400:
                return "Harmony Email & Collaboration answered with an HTTP error; nothing is measured."
        return None

    def hec_body(data):
        """The HEC API answers {"responseEnvelope": {...}, "responseData": [...]}. Unwrap
        Integration-Service wrappers until that shape is found. Returns (body, error): body is
        None when the shape is not found; error is a fixed reason when a wrapper around the body
        carries an error marker, in which case nothing inside it is trusted."""
        for attempt in range(4):
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    return None, None
            if not isinstance(data, dict):
                return None, None
            if isinstance(data.get("responseData"), list):
                return data, None
            err = marker_error(data)
            if err:
                return None, err
            nxt = None
            for key in ("apiResponse", "response", "result", "data", "rawResponse"):
                if isinstance(data.get(key), (dict, str)):
                    nxt = data[key]
                    break
            if nxt is None:
                return None, None
            data = nxt
        return None, None

    def envelope_error(body):
        """Fixed reason when the response body says the call failed, else None."""
        env = body.get("responseEnvelope")
        if isinstance(env, dict):
            code = env.get("responseCode")
            if code is not None and str(code) not in ("200", "0"):
                return "Harmony Email & Collaboration answered with an error status; nothing is measured."
        return marker_error(body)

    def records_total(body):
        """The vendor's recordsNumber as an int, else None."""
        env = body.get("responseEnvelope")
        if isinstance(env, dict):
            try:
                return int(str(env.get("recordsNumber")).strip())
            except Exception:
                return None
        return None

    def more_pages(body):
        """True when the response says records remain beyond this page: a scrollId that is not
        empty (the stored raw form writes null as "None"), or a recordsNumber larger than the
        page. A partial page cannot prove an absence."""
        env = body.get("responseEnvelope")
        for holder in (env if isinstance(env, dict) else {}, body):
            token = holder.get("scrollId")
            if token and str(token).strip().lower() not in ("", "none", "null"):
                return True
        total = records_total(body)
        return total is not None and total > len(body["responseData"])

    def partial_not_measured(what, summary):
        """No verdict: the response is one page of several, so a result that rests on records not
        read cannot be given. `what` names the claim that would need the unread pages."""
        reason = ("The response is a partial page (the vendor reports more records than it returned), so "
                  + what + " is not proven; nothing is measured.")
        return create_response(None, fail_reasons=[reason], api_errors=[reason],
                               input_summary=dict(summary, partialPage=True))

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
        body, err = hec_body(input)
        if err:
            return not_measured(err)
        if body is None:
            return not_measured("No readable Harmony Email & Collaboration response (responseData) in the "
                                "input; nothing is measured.")
        err = envelope_error(body)
        if err:
            return not_measured(err)
        records = [r for r in body["responseData"] if isinstance(r, dict)]
        engine = r"entity_type\W{1,6}(avanan_ap_scan|checkpoint_ap_scan)"
        other = r"entity_type\W{1,6}([a-z0-9_]+_scan)"
        ap = []
        seen_other = {}
        for r in records:
            blob = text(r.get("data")) + " " + json.dumps(r.get("additionalData") or "")
            if re.search(engine, blob):
                ap.append(r)
            else:
                for m in re.findall(other, blob):
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
        if more_pages(body):
            return partial_not_measured("the absence of a Check Point verdict in the unread events", summary)
        return create_response(False, fail_reasons=["No event in the last 30 days carries a Check Point anti-phishing "
                               "engine verdict (avanan_ap_scan / checkpoint_ap_scan)"], input_summary=summary)
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
