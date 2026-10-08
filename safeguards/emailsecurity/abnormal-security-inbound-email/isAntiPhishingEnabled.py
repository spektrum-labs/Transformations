"""
Transformation: isAntiPhishingEnabled
Vendor: Abnormal Security Inbound Email
Method: getThreatDetails  (GET {serverUrl}/v1/threats/{threatId}, threatId = listThreats threats[0])

The method reads ONE threat: the newest. That one threat can show protection is on, and it can
show protection is off, but most threats show neither, so most reads are Unevaluated:

Rules, in this order (a window of 90 calendar days, counted on dates):
- False (measured): ANY phishing-family message within 90 days that Abnormal saw and did NOT act
  on (No Action Done, Would Remediate / detect-only, Not Remediated), wherever it appears in the threat,
  even next to remediated messages.
- True: a message in the threat is a phishing-family attackType (Phishing: Credential /
  Phishing: Sensitive Data / Social Engineering / Invoice/Payment Fraud (BEC) / Scam /
  Extortion) that Abnormal remediated (Remediated / Auto-Remediated / Post Remediated) within
  the last 90 days.
- True (product decision, 3 Oct 2026): otherwise, ANY message in the threat (any attackType, such as
  Spam or Malware) that Abnormal remediated within the last 90 days. Abnormal's inline protection
  cannot be switched off per attack type, so a remediated threat of any kind shows the protection
  that also handles phishing is live and acting.
- None (Unevaluated, reason in dataCollection.errors): an empty, missing or error response, and
  a newest threat with no remediated message in the window (Marked Safe, Remediation Attempted,
  no timestamp, or older than 90 days), and a threat whose messages are paged (nextPageNumber set, or a
  page other than the first) or truncated: an unacted phishing message on an unread page could change the answer. Reading a
  no-evidence threat as False flipped a tenant from True to False on 2 Oct 2026 with no tenant or
  transform change.
"""

import json
import re
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isAntiPhishingEnabled',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)

WINDOW_DAYS = 90
PHISHING_FAMILY = ["phishing", "social engineering", "invoice/payment fraud", "bec", "scam", "extortion"]
TS_PATTERN = r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"


def extract_input(input_data):
    if isinstance(input_data, str):
        input_data = json.loads(input_data)
    elif isinstance(input_data, bytes):
        input_data = json.loads(input_data.decode("utf-8"))
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for step in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "isAntiPhishingEnabled",
                "vendor": "Abnormal Security Inbound Email",
                "category": "emailsecurity",
            },
        },
    }


def parse_ts(value):
    if not isinstance(value, str):
        return None
    m = re.match(TS_PATTERN, value)
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                        int(m.group(4)), int(m.group(5)), int(m.group(6)))
    except ValueError:
        return None


def is_phishing_family(attack_type):
    t = str(attack_type or "").lower()
    for kw in PHISHING_FAMILY:
        if kw in t:
            return True
    return False


def is_remediated(status):
    s = str(status or "").lower().strip()
    if not s or "not" in s or "attempt" in s or "would" in s:
        return False
    return s in ["remediated", "auto-remediated", "auto remediated", "post remediated", "post-remediated"]


def is_detect_only(status):
    s = str(status or "").lower().strip()
    return s in ["no action done", "would remediate", "not remediated"]


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"
    try:
        data, validation = extract_input(input)
        messages = data.get("messages") if isinstance(data, dict) else None
        if not isinstance(messages, list):
            messages = []
        messages = [m for m in messages if isinstance(m, dict)]
        threat_id = data.get("threatId") if isinstance(data, dict) else None

        if not messages:
            reason = "No threat messages in the Abnormal response (empty, error or missing threat detail); nothing to measure"
            return create_response(
                result={criteriaKey: None, "remediatedPhishingMessages": 0, "messagesEvaluated": 0},
                validation=validation, api_errors=[reason], fail_reasons=[reason],
                recommendations=["Confirm the Abnormal REST API token is valid and the tenant has threat data at /v1/threats."],
                input_summary={"threatId": threat_id, "messagesEvaluated": 0, "windowDays": WINDOW_DAYS})

        next_page = data.get("nextPageNumber") if isinstance(data, dict) else None
        truncated = isinstance(data, dict) and (data.get("paginationTruncated") is True
                                                or str(data.get("truncated")).lower() == "true")
        page_number = data.get("pageNumber") if isinstance(data, dict) else None
        later_page = page_number not in (None, "", 1, "1", "None", "null")
        if (next_page not in (None, "", 0, "0", "None", "null")) or truncated or later_page:
            reason = ("The Abnormal threat detail is paged (pageNumber=%r, nextPageNumber=%r) or truncated, so an "
                      "unacted phishing message on an unread page cannot be ruled out; not scored"
                      % (page_number, next_page))
            return create_response(
                result={criteriaKey: None, "messagesEvaluated": len(messages)},
                validation=validation, api_errors=[reason], fail_reasons=[reason],
                input_summary={"threatId": threat_id, "messagesEvaluated": len(messages),
                               "nextPageNumber": next_page, "windowDays": WINDOW_DAYS})

        now = datetime.utcnow()
        evidence = []
        unacted = []
        any_remediated = []
        attack_types = []
        statuses = []
        for m in messages:
            at = m.get("attackType")
            rs = m.get("remediationStatus")
            if at and at not in attack_types:
                attack_types.append(at)
            if rs and rs not in statuses:
                statuses.append(rs)
            when = parse_ts(m.get("remediationTimestamp")) or parse_ts(m.get("sentTime"))
            age_days = (now.date() - when.date()).days if when is not None else None
            recent = age_days is not None and -1 <= age_days <= WINDOW_DAYS
            if recent and is_remediated(rs):
                any_remediated.append({"attackType": at, "remediationStatus": rs,
                                       "when": m.get("remediationTimestamp") or m.get("sentTime")})
            if not (is_phishing_family(at) and recent):
                continue
            row = {"attackType": at, "remediationStatus": rs, "when": m.get("remediationTimestamp") or m.get("sentTime")}
            if is_remediated(rs):
                evidence.append(row)
            elif is_detect_only(rs):
                unacted.append(row)

        summary = {
            "threatId": threat_id,
            "messagesEvaluated": len(messages),
            "remediatedPhishingMessages": len(evidence),
            "unremediatedPhishingMessages": len(unacted),
            "remediatedMessagesAnyType": len(any_remediated),
            "attackTypesObserved": attack_types,
            "remediationStatusesObserved": statuses,
            "windowDays": WINDOW_DAYS,
        }
        result = {criteriaKey: None, "remediatedPhishingMessages": len(evidence),
                  "unremediatedPhishingMessages": len(unacted), "messagesEvaluated": len(messages)}
        if unacted:
            e = unacted[0]
            result[criteriaKey] = False
            return create_response(
                result=result, validation=validation, input_summary=summary,
                fail_reasons=[
                    "Abnormal classified an inbound message as %r within %d days and did not remediate it "
                    "(remediationStatus=%r, %s): phishing was detected but not acted on."
                    % (e["attackType"], WINDOW_DAYS, e["remediationStatus"], e["when"])],
                recommendations=["Confirm Abnormal inbound protection runs in remediation (not detect-only) mode."])
        if evidence:
            e = evidence[0]
            result[criteriaKey] = True
            return create_response(
                result=result, validation=validation, input_summary=summary,
                pass_reasons=[
                    "Abnormal classified an inbound message as %r and remediated it (remediationStatus=%r, %s); "
                    "%d of %d message(s) in threat %s are remediated phishing-family attacks within %d days."
                    % (e["attackType"], e["remediationStatus"], e["when"], len(evidence), len(messages),
                       threat_id, WINDOW_DAYS)])
        if any_remediated:
            e = any_remediated[0]
            result[criteriaKey] = True
            return create_response(
                result=result, validation=validation, input_summary=summary,
                pass_reasons=[
                    "Abnormal remediated an inbound %r message within %d days (remediationStatus=%r, %s): the inline "
                    "protection, which also handles phishing and cannot be switched off per attack type, is live "
                    "and acting (%d of %d message(s) in threat %s remediated)."
                    % (e["attackType"], WINDOW_DAYS, e["remediationStatus"], e["when"], len(any_remediated),
                       len(messages), threat_id)])
        reason = (
            "The newest Abnormal threat (%s) has no message Abnormal remediated in the last %d days "
            "(attackTypes=%s, remediationStatuses=%s), so whether protection is acting cannot be shown"
            % (threat_id, WINDOW_DAYS, attack_types, statuses))
        return create_response(
            result=result, validation=validation, input_summary=summary,
            api_errors=[reason], fail_reasons=[reason])
    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
