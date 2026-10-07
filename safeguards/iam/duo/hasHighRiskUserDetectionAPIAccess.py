import json
from datetime import datetime

# hasHighRiskUserDetectionAPIAccess -- do Duo authentication logs carry risk-based trust
# assessments (Risk-Based Authentication) for authentication events?
#
# Source: GET /admin/v2/logs/authentication (method getAuthLogs, returnSpec
# {"authlogs": [...], "metadata": {...}}). Each record may carry
# adaptive_trust_assessments: Duo Risk-Based Authentication's per-event trust verdict
# ("more_secure_auth" = Risk-Based Factor Selection, "remember_me" = Risk-Based
# Remembered Devices), each with trust_level, reason and detected_attack_detectors.
# Duo documents it for Premier and Advantage plans, on applications using the Universal
# Prompt. The Trust Monitor events endpoint is not used: Duo closed it to customers
# created after 2025-09-29 and ends its support on 2027-01-31.
#
# Reports whether Duo authentication logs carry risk-based trust assessments.
# Verdict: true when Duo answers the authentication logs call (an authlogs list with Duo's
# paging metadata) and at least one event carries a trust assessment (riskScoredEventCount
# > 0). Events present but none assessed is NOT false: absence cannot tell "plan lacks
# Risk-Based Authentication", "policy not enabled" and "no Universal Prompt apps" apart, and
# none of them is a setting the customer got wrong, so it is reported as a data-collection
# error with a null verdict (also when the window is truncated at the 1000-event request
# limit). riskAssessedAuthPercentage reports how much of the window was assessed. No authlogs
# key, no paging metadata, or an empty window proves nothing (an error body collapses to
# the returnSpec defaults) and is likewise null. Only the 403/40301 refusal below is false.
#
# Duo answers 403 {"code": 40301, "message": "Access forbidden"} when the Admin API
# application lacks "Grant read log". Integration-Service hands that one refusal over
# as data (getAuthLogs opts in via vendorErrorAsResponse) as
#   {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}
# and skips the returnSpec for it. That refusal is a measured false; any other marked
# vendor error is a data-collection error with a null verdict.

KEY = "hasHighRiskUserDetectionAPIAccess"
REQUEST_LIMIT = 1000


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Duo",
                "category": "iam",
            },
        },
    }


def trust_levels(record):
    """The trust_level of each adaptive trust assessment on one auth record."""
    levels = []
    assessments = record.get("adaptive_trust_assessments") if isinstance(record, dict) else None
    if not isinstance(assessments, dict):
        return levels
    for name in assessments:
        item = assessments[name]
        if isinstance(item, dict) and item.get("trust_level") not in (None, ""):
            levels.append(str(item.get("trust_level")).upper())
    return levels


def duo_access_forbidden(marker):
    """True only for the marked 403 / 40301 "Access forbidden" refusal."""
    if not isinstance(marker, dict) or marker.get("status") != 403:
        return False
    body = marker.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return False
    return isinstance(body, dict) and body.get("code") == 40301 and body.get("message") == "Access forbidden"


def transform(input):
    if isinstance(input, (str, bytes)):
        try:
            input = json.loads(input)
        except ValueError:
            input = {}
    data, validation = extract_input(input)

    if isinstance(data, dict) and "vendorErrorAsResponse" in data:
        marker = data.get("vendorErrorAsResponse")
        if duo_access_forbidden(marker):
            return create_response(
                result={KEY: False, "riskScoredEventCount": None}, validation=validation,
                input_summary={"vendorStatus": 403, "vendorCode": 40301},
                fail_reasons=["Duo refused the v2 authentication logs (/admin/v2/logs/authentication) with HTTP 403, "
                              "code 40301 \"Access forbidden\": the admin API key lacks Grant read log permission, "
                              "so no per-event risk assessment is available to Spektrum."],
                recommendations=["In the Duo Admin Panel, open the Admin API application used for Spektrum and "
                                 "enable the \"Grant read log\" permission."],
            )
        return create_response(
            result={KEY: None, "riskScoredEventCount": None}, validation=validation,
            api_errors=["Duo returned an error instead of authentication log data: %s" % str(marker)[:300]],
        )

    records = data.get("authlogs") if isinstance(data, dict) else None
    metadata = data.get("metadata") if isinstance(data, dict) else None
    complete = isinstance(records, list) and isinstance(metadata, dict) and "total_objects" in metadata
    events = [rec for rec in records if isinstance(rec, dict)] if complete else []
    if not events:
        return create_response(
            result={KEY: None, "riskScoredEventCount": None},
            validation=validation,
            api_errors=["No Duo v2 authentication log events (authlogs with paging metadata) in the response."],
        )

    total = 0
    assessed = 0
    low_trust = 0
    users = []
    for rec in events:
        total = total + 1
        levels = trust_levels(rec)
        if levels:
            assessed = assessed + 1
            user = rec.get("user") if isinstance(rec.get("user"), dict) else {}
            name = user.get("name") or user.get("key")
            if name and name not in users:
                users.append(name)
            if "LOW" in levels:
                low_trust = low_trust + 1

    pct = round(100.0 * assessed / total, 1) if total else 0.0
    summary = {
        "totalAuthEvents": total,
        "riskScoredEventCount": assessed,
        "riskAssessedAuthCount": assessed,
        "riskAssessedAuthPercentage": pct,
        "lowTrustAuthCount": low_trust,
        "riskAssessedUserCount": len(users),
    }
    if assessed == 0:
        window = ("the window is at the %d-event request limit, so assessments may lie beyond it; "
                  % REQUEST_LIMIT) if total >= REQUEST_LIMIT else ""
        result = {KEY: None}
        result.update(summary)
        return create_response(
            result=result, validation=validation, input_summary=summary,
            api_errors=["Not evaluated: no risk-based trust assessments (adaptive_trust_assessments) were found in "
                        "%d Duo v2 authentication log events (/admin/v2/logs/authentication). %sThis can mean the "
                        "Duo plan lacks risk-based authentication, the feature is not enabled, or no applications "
                        "use the Universal Prompt, so whether risk detection is available cannot be determined."
                        % (total, window)],
        )
    result = {KEY: True}
    result.update(summary)
    reason = ("Duo Admin API v2 authentication logs (/admin/v2/logs/authentication) surface risk scoring: %d events "
              "returned, %d (%.1f%%) carry Risk-Based Authentication trust assessments "
              "(adaptive_trust_assessments), across %d users; %d rated LOW trust."
              % (total, assessed, pct, len(users), low_trust))
    return create_response(
        result=result, validation=validation, input_summary=summary, pass_reasons=[reason],
    )
