"""\nTransformation: isMFAEnforcedForUsers\nVendor: Duo  |  Category: IAM\nEvaluates: Whether all active Duo users have at least one MFA device enrolled\n(phone, hardware token, or WebAuthn credential), reducing the risk of account takeover.\n"""
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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
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
                "transformationId": "isMFAEnforcedForUsers",
                "vendor": "Duo",
                "category": "IAM"
            }
        }
    }


def has_mfa_enrolled(user):
    """Return True if the user has at least one enrolled MFA device."""
    phones = user.get("phones", [])
    tokens = user.get("tokens", [])
    webauthn = user.get("webauthncredentials", [])
    return len(phones) > 0 or len(tokens) > 0 or len(webauthn) > 0


def evaluate(data):
    """
    Inspect the users list returned by getUsers.
    Only 'active' status users are evaluated -- 'bypass' and 'disabled'
    users are excluded since they either cannot authenticate normally
    or are not active accounts.
    A user passes if they have at least one enrolled phone, hardware token,
    or WebAuthn credential.
    """
    users = data.get("users", [])

    if not isinstance(users, list):
        return {
            "isMFAEnforcedForUsers": False,
            "error": "Unexpected data shape: 'users' is not a list"
        }

    total_users = len(users)
    active_users = [u for u in users if u.get("status", "") == "active"]
    bypass_users = [u for u in users if u.get("status", "") == "bypass"]
    disabled_users = [u for u in users if u.get("status", "") == "disabled"]

    total_active = len(active_users)
    total_bypass = len(bypass_users)
    total_disabled = len(disabled_users)

    non_compliant = [u for u in active_users if not has_mfa_enrolled(u)]
    compliant_count = total_active - len(non_compliant)
    non_compliant_count = len(non_compliant)

    non_compliant_usernames = [u.get("username", u.get("user_id", "unknown")) for u in non_compliant]

    score_in_percentage = 0
    if total_active > 0:
        score_in_percentage = int((compliant_count * 100) / total_active)

    is_enforced = non_compliant_count == 0 and total_active > 0

    return {
        "isMFAEnforcedForUsers": is_enforced,
        "totalUsers": total_users,
        "totalActiveUsers": total_active,
        "totalBypassUsers": total_bypass,
        "totalDisabledUsers": total_disabled,
        "compliantCount": compliant_count,
        "nonCompliantCount": non_compliant_count,
        "nonCompliantUsernames": non_compliant_usernames,
        "scoreInPercentage": score_in_percentage
    }


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_active = eval_result.get("totalActiveUsers", 0)
        non_compliant_count = eval_result.get("nonCompliantCount", 0)
        score = eval_result.get("scoreInPercentage", 0)
        non_compliant_usernames = eval_result.get("nonCompliantUsernames", [])
        total_bypass = eval_result.get("totalBypassUsers", 0)

        if "error" in eval_result:
            fail_reasons.append(eval_result["error"])
        elif total_active == 0:
            fail_reasons.append("No active users found -- cannot confirm MFA enforcement")
            recommendations.append("Ensure the Duo integration has 'Grant read resource' permission and active users exist")
        elif result_value:
            pass_reasons.append(
                "All " + str(total_active) + " active user(s) have at least one MFA device enrolled"
            )
            pass_reasons.append("MFA enrollment score: " + str(score) + "%")
        else:
            fail_reasons.append(
                str(non_compliant_count) + " of " + str(total_active) +
                " active user(s) have no MFA device enrolled"
            )
            fail_reasons.append("MFA enrollment score: " + str(score) + "%")
            recommendations.append(
                "Require all active users to enroll at least one MFA device "
                "(phone, hardware token, or WebAuthn credential) in Duo"
            )
            recommendations.append(
                "Consider enabling the Duo 'New User Policy' to block access until enrollment is complete"
            )
            if len(non_compliant_usernames) > 0:
                additional_findings.append(
                    "Users without MFA enrolled: " + ", ".join(non_compliant_usernames[:20])
                )

        if total_bypass > 0:
            additional_findings.append(
                str(total_bypass) + " user(s) are in 'bypass' status and were excluded from evaluation -- "
                "review whether bypass is still required for those accounts"
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalUsers": eval_result.get("totalUsers", 0),
                "totalActiveUsers": total_active,
                "compliantCount": eval_result.get("compliantCount", 0),
                "nonCompliantCount": non_compliant_count,
                "scoreInPercentage": score
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
