import json
from datetime import datetime

# hasHighRiskUserDetectionAPIAccess -- does Duo's API surface heuristic risk scoring of
# authentication events, per user?
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
# Verdict: true when at least one authentication event in the window carries a trust
# assessment. riskAssessedAuthPercentage reports how much of the window was assessed.
# No authlogs key, or an empty authlogs list without Duo's paging metadata, proves
# nothing (an error body collapses to the returnSpec defaults) and is reported as a
# data-collection error, never judged.
#
# Duo answers 403 {"code": 40301, "message": "Access forbidden"} when the Admin API
# application lacks "Grant read log". Integration-Service hands that one refusal over
# as data (getAuthLogs opts in via vendorErrorAsResponse) as
#   {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}
# and skips the returnSpec for it. That refusal is a measured false; any other marked
# vendor error is a data-collection error.

KEY = "hasHighRiskUserDetectionAPIAccess"


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
        empty = {KEY: False, "riskAssessedAuthPercentage": 0.0, "totalAuthEvents": 0}
        if duo_access_forbidden(marker):
            return create_response(
                result=empty, validation=validation,
                input_summary={"vendorStatus": 403, "vendorCode": 40301},
                fail_reasons=["Duo refused the v2 authentication logs (/admin/v2/logs/authentication) with HTTP 403, "
                              "code 40301 \"Access forbidden\": the admin API key lacks Grant read log permission, "
                              "so no per-event risk assessment is available to Spektrum."],
                recommendations=["In the Duo Admin Panel, open the Admin API application used for Spektrum and "
                                 "enable the \"Grant read log\" permission."],
            )
        return create_response(
            result=empty, validation=validation,
            api_errors=["Duo returned an error instead of authentication log data: %s" % str(marker)[:300]],
        )

    records = data.get("authlogs") if isinstance(data, dict) else None
    metadata = data.get("metadata") if isinstance(data, dict) else None
    genuine_zero = isinstance(records, list) and not records and isinstance(metadata, dict) \
        and "total_objects" in metadata
    if not isinstance(records, list) or (not records and not genuine_zero):
        return create_response(
            result={KEY: False, "riskAssessedAuthPercentage": 0.0, "totalAuthEvents": 0},
            validation=validation,
            api_errors=["No Duo v2 authentication log data (authlogs with paging metadata) in the response."],
        )

    total = 0
    assessed = 0
    low_trust = 0
    users = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
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
    has_access = assessed > 0
    summary = {
        "totalAuthEvents": total,
        "riskAssessedAuthCount": assessed,
        "riskAssessedAuthPercentage": pct,
        "lowTrustAuthCount": low_trust,
        "riskAssessedUserCount": len(users),
    }
    result = {KEY: has_access}
    result.update(summary)

    if has_access:
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=[
                "Duo Admin API v2 authentication logs carry Risk-Based Authentication trust assessments "
                "(adaptive_trust_assessments) on %d of %d events (%.1f%%), across %d users; %d rated LOW trust."
                % (assessed, total, pct, len(users), low_trust)
            ],
        )
    if total == 0:
        reason = ("Duo Admin API v2 authentication logs returned no authentication events in the window, "
                  "so no per-event risk assessment was surfaced.")
    else:
        reason = ("None of the %d authentication events returned by the Duo Admin API v2 authentication logs "
                  "carries a Risk-Based Authentication trust assessment (adaptive_trust_assessments)." % total)
    return create_response(
        result=result, validation=validation, input_summary=summary,
        fail_reasons=[reason],
        recommendations=[
            "Duo surfaces per-event risk scoring through Risk-Based Authentication (Premier or Advantage plan) "
            "on applications using the Universal Prompt; enable it so authentication logs carry trust assessments."
        ],
    )
