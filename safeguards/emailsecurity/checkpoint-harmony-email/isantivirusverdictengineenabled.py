"""
Transformation: isAntivirusVerdictEngineEnabled
Vendor: Check Point Harmony Email & Collaboration (Infinity Portal API)
Method: searchAttachmentEmails (POST /app/hec-api/v1.0/search/query, office365_emails_email, attachmentCount > 0, last 7 days)

True when at least one email entity with attachments returned by the entity search carries an
antivirus result: entitySecurityResult.av is a non-empty list with a verdict, or
entitySecurityResult.combinedVerdict.av is set (API reference, Get the Details of a Specific
Entity: combinedVerdict.av = Antivirus verdict). Entities without an av result, or no entity with
attachments in the window, read false. The field name entitySecurityResult was measured on a live
payload (27 Oct 2026); the API reference spells it entitySecurityResults, and both are read.
Not evaluated (None, with a data-collection error) when the body is an error, empty or unrecognised:
it proves nothing, so it is never reported as False. A readable answer that lists nothing keeps the
verdict described above.
One page of a paged answer is not the whole window: when the response carries a scrollId or a
recordsNumber above the page, a match already seen still counts, but an absence is not proven, so a
page with no match reads None (Not evaluated) and never False.
An entry that cannot be read is never skipped: one that is not an object, or a field that should
hold JSON and does not parse. The unread entry may hold the match, so an absence reads None; a match
already seen keeps its verdict. A missing, blank or "None" field is a readable empty one.
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
        """The vendor's recordsNumber as a whole number, else None. None also covers a total that is
        stated but cannot be read (see total_unreadable)."""
        env = body.get("responseEnvelope")
        value = env.get("recordsNumber") if isinstance(env, dict) else None
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value if value >= 0 else None
        if isinstance(value, str):
            digits = value.strip()
            if digits.isdecimal():
                return int(digits)
        return None

    def total_unreadable(body):
        """True when the vendor states a recordsNumber that cannot be read as a whole number, so
        whether the page is complete is unknown. A missing, null or blank total states nothing."""
        env = body.get("responseEnvelope")
        value = env.get("recordsNumber") if isinstance(env, dict) else None
        if value is None or (isinstance(value, str) and value.strip().lower() in ("", "none", "null")):
            return False
        return records_total(body) is None

    def more_pages(body):
        """"more" when the response says records remain beyond this page: a scrollId that is not
        empty (the stored raw form writes null as "None"), or a recordsNumber larger than the page.
        "unknown" when it states a recordsNumber that cannot be read, so nobody knows whether the page
        is complete. "" when the page is complete. Anything but "" cannot prove an absence.
        A live search answer carries a scrollId on its last page too, so a page whose recordsNumber
        equals its length still reads "more" here: deliberately conservative (None, never a false
        verdict), left for a follow-up that changes every presence check together."""
        env = body.get("responseEnvelope")
        for holder in (env if isinstance(env, dict) else {}, body):
            token = holder.get("scrollId")
            if token and str(token).strip().lower() not in ("", "none", "null"):
                return "more"
        total = records_total(body)
        if total is not None and total > len(body["responseData"]):
            return "more"
        if total_unreadable(body):
            return "unknown"
        return ""

    def unproven(what, summary, partial, unreadable):
        """No verdict: `what` rests on records that were not read, because the response is one page
        of several (partial) or holds entries that could not be read (unreadable). Fixed text."""
        causes = []
        if partial == "unknown":
            causes.append("the vendor's record total could not be read, so the response may be a partial page")
        elif partial:
            causes.append("the response is a partial page (the vendor reports more records than it returned)")
        if unreadable:
            causes.append(str(unreadable) + (" entry" if unreadable == 1 else " entries") +
                          " in the response could not be read")
        reason = "; ".join(causes)
        reason = reason[:1].upper() + reason[1:] + ", so " + what + " is not proven; nothing is measured."
        return create_response(None, fail_reasons=[reason], api_errors=[reason],
                               input_summary=dict(summary, partialPage=(partial == "more"),
                                                  recordsNumberUnreadable=(partial == "unknown"),
                                                  unreadableEntries=unreadable))

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

    def read_json(value):
        """(parsed, readable). A missing, blank or "None" value is readable and empty (None). Text is
        parsed as JSON and text that does not parse is not readable. Anything else is returned as is."""
        if isinstance(value, str):
            if text(value) == "":
                return None, True
            try:
                return json.loads(value), True
            except Exception:
                return None, False
        return value, True

    def security_result(entity):
        """The entity's security-result block under either spelling: entitySecurityResult (what the
        live search API returns) or entitySecurityResults (the API reference). A present key wins
        even when empty, so a blank singular is not masked by a stale plural."""
        if "entitySecurityResult" in entity:
            return entity.get("entitySecurityResult")
        return entity.get("entitySecurityResults")

    def read_object(value):
        """(object, readable): a dict, or JSON text holding one. A missing, blank or "None" value and
        an empty list are readable and empty (None); any other value is not readable."""
        parsed, readable = read_json(value)
        if not readable:
            return None, False
        if parsed is None or parsed == []:
            return None, True
        if isinstance(parsed, dict):
            return parsed, True
        return None, False

    def read_actions(record):
        """(actions, readable): the action objects of an event record. A missing, blank or "None"
        actions field is readable and empty. Text that is not JSON, a value that is not a list, or an
        entry that is not an object makes the record not readable."""
        acts, readable = read_json(record.get("actions"))
        if not readable:
            return [], False
        if acts is None:
            return [], True
        if not isinstance(acts, list):
            return [], False
        good = [a for a in acts if isinstance(a, dict)]
        return good, len(good) == len(acts)

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
        unreadable = len(body["responseData"]) - len(records)
        def av_verdict(sr):
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
        entities = []
        scanned = []
        verdicts = {}
        for e in records:
            info, info_ok = read_object(e.get("entityInfo"))
            # The live search API names the block entitySecurityResult (singular, measured on a real
            # tenant 27 Oct 2026); the API reference and older fixtures spell it entitySecurityResults.
            results, results_ok = read_object(security_result(e))
            if not (info_ok and results_ok):
                unreadable = unreadable + 1
                continue
            if info is None and results is None:
                continue
            entities.append(e)
            v = av_verdict(results)
            if v:
                scanned.append(e)
                verdicts[v.lower()] = verdicts.get(v.lower(), 0) + 1
        summary = {"entitiesOnFirstPage": len(entities), "entitiesWithAvVerdict": len(scanned),
                   "avVerdicts": verdicts, "windowDays": 7}
        if scanned:
            return create_response(True, pass_reasons=[str(len(scanned)) + " of " + str(len(entities)) + " email(s) with "
                                   "attachments carry a Check Point antivirus verdict (security result av)"],
                                   input_summary=summary)
        partial = more_pages(body)
        if partial or unreadable:
            return unproven("the absence of an antivirus verdict on the emails not yet read", summary, partial, unreadable)
        if not entities:
            return create_response(False, fail_reasons=["The entity search returned no email with attachments in the "
                                   "last 7 days, so the antivirus engine's verdicts are not evidenced"], input_summary=summary)
        return create_response(False, fail_reasons=["None of the " + str(len(entities)) + " email(s) with attachments "
                               "carries an antivirus verdict (entitySecurityResult.av empty)"], input_summary=summary)
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
