"""
Transformation: isAntiPhishingEnabled
Vendor: Abnormal Security Inbound Email
Method: getThreatDetails  (GET {serverUrl}/v1/threats/{threatId}, threatId = listThreats threats[0])

True only when the threat detail shows Abnormal ACTING on phishing for this tenant:
at least one message in the threat is classified with a phishing-family attackType
(Phishing: Credential / Phishing: Sensitive Data / Social Engineering / Invoice/Payment
Fraud (BEC) / Scam / Extortion), carries a remediated remediationStatus, and was
remediated (or sent) within the last 30 days. Everything else fails closed: an empty or
missing messages list, an error envelope, a detect-only status (Not Remediated, No Action
Done, Remediation Attempted, Marked Safe), a non-phishing type (Malware, Spam, Other), or
a threat older than 30 days.
"""

import json
import re
from datetime import datetime

WINDOW_DAYS = 30
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


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"
    try:
        data, validation = extract_input(input)
        messages = data.get("messages") if isinstance(data, dict) else None
        if not isinstance(messages, list):
            messages = []

        now = datetime.utcnow()
        evidence = []
        attack_types = []
        statuses = []
        for m in messages:
            if not isinstance(m, dict):
                continue
            at = m.get("attackType")
            rs = m.get("remediationStatus")
            if at and at not in attack_types:
                attack_types.append(at)
            if rs and rs not in statuses:
                statuses.append(rs)
            when = parse_ts(m.get("remediationTimestamp")) or parse_ts(m.get("sentTime"))
            recent = when is not None and (now - when).days <= WINDOW_DAYS and (now - when).days >= -1
            if is_phishing_family(at) and is_remediated(rs) and recent:
                evidence.append({"attackType": at, "remediationStatus": rs,
                                 "when": m.get("remediationTimestamp") or m.get("sentTime")})

        enabled = len(evidence) > 0
        summary = {
            "threatId": data.get("threatId") if isinstance(data, dict) else None,
            "messagesEvaluated": len(messages),
            "remediatedPhishingMessages": len(evidence),
            "attackTypesObserved": attack_types,
            "remediationStatusesObserved": statuses,
            "windowDays": WINDOW_DAYS,
        }
        pass_reasons, fail_reasons, recs = [], [], []
        if enabled:
            e = evidence[0]
            pass_reasons.append(
                "Abnormal classified an inbound message as %r and remediated it (remediationStatus=%r, %s); "
                "%d of %d message(s) in threat %s are remediated phishing-family attacks within %d days."
                % (e["attackType"], e["remediationStatus"], e["when"], len(evidence), len(messages),
                   summary["threatId"], WINDOW_DAYS))
        elif not messages:
            fail_reasons.append("No threat messages in the response (empty, error or missing threat detail).")
            recs.append("Confirm the Abnormal REST API token is valid and the tenant has threat data at /v1/threats.")
        else:
            fail_reasons.append(
                "No message is a phishing-family attack remediated within %d days (attackTypes=%s, remediationStatuses=%s)."
                % (WINDOW_DAYS, attack_types, statuses))
            recs.append("Confirm Abnormal inbound protection runs in remediation (not detect-only) mode.")

        return create_response(
            result={criteriaKey: enabled, "remediatedPhishingMessages": len(evidence), "messagesEvaluated": len(messages)},
            validation=validation, pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recs, input_summary=summary)
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
