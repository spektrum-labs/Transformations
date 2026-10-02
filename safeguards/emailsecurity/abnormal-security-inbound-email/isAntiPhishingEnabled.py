"""
Transformation: isAntiPhishingEnabled
Vendor: Abnormal Security Inbound Email
Method: getThreatDetails  (GET {serverUrl}/v1/threats/{threatId}, threatId = listThreats threats[0])

The method reads ONE threat: the newest. That one threat can show protection is on, and it can
show protection is off, but most threats show neither, so most reads are Unevaluated:

- True: a message in the threat is a phishing-family attackType (Phishing: Credential /
  Phishing: Sensitive Data / Social Engineering / Invoice/Payment Fraud (BEC) / Scam /
  Extortion) that Abnormal remediated (Remediated / Auto-Remediated / Post Remediated) within
  the last 90 days.
- False (measured): a phishing-family message within 90 days that Abnormal saw and did NOT act
  on: remediationStatus No Action Done, Would Remediate (detect-only) or Not Remediated.
- None (Unevaluated, reason in dataCollection.errors): an empty, missing or error response, and
  a newest threat that is neither of the above (a non-phishing type such as Spam or Malware,
  Marked Safe, Remediation Attempted, no timestamp, or older than 90 days). One threat of that
  kind says nothing about whether anti-phishing is on; reading it as False flipped THL Partners
  from True to False on 2 Oct 2026 with no tenant or transform change.
"""

import json
import re
from datetime import datetime

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

        now = datetime.utcnow()
        evidence = []
        unacted = []
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
            recent = when is not None and (now - when).days <= WINDOW_DAYS and (now - when).days >= -1
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
            "attackTypesObserved": attack_types,
            "remediationStatusesObserved": statuses,
            "windowDays": WINDOW_DAYS,
        }
        result = {criteriaKey: None, "remediatedPhishingMessages": len(evidence),
                  "unremediatedPhishingMessages": len(unacted), "messagesEvaluated": len(messages)}
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
        reason = (
            "The newest Abnormal threat (%s) is not a phishing-family attack from the last %d days with a "
            "remediated or detect-only status (attackTypes=%s, remediationStatuses=%s); one such threat cannot "
            "show whether anti-phishing is on, so there is nothing to measure"
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
