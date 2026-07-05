"""
Transformation: isURLRewriteEnabled
Vendor: Microsoft
Category: Email Security

Evaluates if URL rewrite is enabled for email security.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isURLRewriteEnabled",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }



def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

def transform(input):
    criteriaKey = "isURLRewriteEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )


        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(data.get('PSError', ''), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        controlName = "mdo_safelinksforemail"

        # LABS-3088: Today this criterion is fed subscribedSkus, which has no urlRewrite flag.
        # After the Integration-Service repoint, it receives secureScores; mirror
        # issafelinksenabled.py and evaluate the Safe Links for email control.
        values = data.get("value") or []
        if (isinstance(values, list) and len(values) > 0 and isinstance(values[0], dict)
                and isinstance(values[0].get("controlScores"), list)):
            control_scores = values[0].get("controlScores") or []
            matched_object_list = [
                i for i in control_scores
                if isinstance(i, dict) and i.get("controlName") == controlName
            ]
            score_in_percentage = 0.0
            count = 0
            total = 0

            if len(matched_object_list) == 1:
                matched_object = matched_object_list[0]

                raw_score = matched_object.get("scoreInPercentage", 0.0)
                if isinstance(raw_score, str):
                    try:
                        score_in_percentage = float(raw_score)
                    except ValueError:
                        score_in_percentage = 0.0
                else:
                    score_in_percentage = raw_score
                is_enabled = score_in_percentage == 100.00

                raw_count = matched_object.get("count", 0)
                raw_total = matched_object.get("total", 0)
                if isinstance(raw_count, str):
                    try:
                        count = int(raw_count)
                    except ValueError:
                        count = 0
                else:
                    count = raw_count or 0
                if isinstance(raw_total, str):
                    try:
                        total = int(raw_total)
                    except ValueError:
                        total = 0
                else:
                    total = raw_total or 0

                if is_enabled:
                    pass_reasons.append(
                        f"Safe Links URL rewrite enabled (Secure Score control '{controlName}' at 100%)")
                else:
                    fail_reasons.append(
                        f"Safe Links URL rewrite score is {score_in_percentage}% (control '{controlName}')")
                    recommendations.append(
                        "Enable Safe Links URL rewrite in the Microsoft Defender for Office 365 policy")
            else:
                is_enabled = False
                fail_reasons.append(f"Secure Score control '{controlName}' not found in Secure Score")
                recommendations.append(
                    "Verify Microsoft Defender for Office 365 (Safe Links) is licensed and configured")

            return create_response(
                result={
                    criteriaKey: is_enabled,
                    "scoreInPercentage": score_in_percentage,
                    "count": count,
                    "total": total
                },
                validation=validation,
                pass_reasons=pass_reasons,
                fail_reasons=fail_reasons,
                recommendations=recommendations,
                input_summary={
                    "urlRewriteEnabled": is_enabled,
                    "source": "secureScore",
                    "controlName": controlName,
                    "scoreInPercentage": score_in_percentage,
                    "protectedCount": count,
                    "totalCount": total
                }
            )

        is_enabled = bool(data.get('urlRewrite', False))

        if is_enabled:
            pass_reasons.append("URL rewrite is enabled for email security")
        else:
            fail_reasons.append("URL rewriting/Safe Links not enabled")
            recommendations.append("Enable URL rewrite in Safe Links policy to protect against malicious URLs")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"urlRewriteEnabled": is_enabled}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
