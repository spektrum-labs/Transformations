"""
Transformation: confirmedLicensePurchased
Vendor: Rubrik  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Confirms the Rubrik Security Cloud subscription is active by verifying that
authenticated API access returns a valid currentUser object with a non-empty email address
and at least one assigned role — indicating a licensed RSC instance is in use.
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Rubrik",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def extract_current_user(data):
    """
    Extract currentUser object from multiple possible data shapes.
    getCurrentUser returnSpec: data = data.currentUser
    So the transformation input 'data' field should be the currentUser object
    with shape {email, roles: [{name, description}]}
    """
    if isinstance(data, dict):
        if "email" in data:
            return data
        inner = data.get("data", None)
        if isinstance(inner, dict) and "email" in inner:
            return inner
        user = data.get("currentUser", None)
        if isinstance(user, dict):
            return user
        if isinstance(inner, dict):
            user2 = inner.get("currentUser", None)
            if isinstance(user2, dict):
                return user2
    return {}


def evaluate(data):
    """Core evaluation logic for confirmedLicensePurchased."""
    try:
        user = extract_current_user(data)

        email = user.get("email", "")
        roles = user.get("roles", [])
        if not isinstance(roles, list):
            roles = []

        has_valid_email = isinstance(email, str) and len(email) > 0
        has_roles = len(roles) > 0

        role_names = [r.get("name", "unknown") for r in roles if isinstance(r, dict)]

        confirmed_license_purchased = has_valid_email and has_roles

        return {
            "confirmedLicensePurchased": confirmed_license_purchased,
            "authenticatedUserEmail": email,
            "assignedRoleCount": len(role_names),
            "assignedRoles": role_names,
            "hasValidEmail": has_valid_email,
            "hasAssignedRoles": has_roles
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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

        if result_value:
            pass_reasons.append(
                "Rubrik Security Cloud subscription confirmed active: authenticated API access "
                "returned a valid user object with email and assigned roles"
            )
            pass_reasons.append(
                "Authenticated as: " + eval_result.get("authenticatedUserEmail", "unknown")
            )
            role_names = eval_result.get("assignedRoles", [])
            if role_names:
                additional_findings.append(
                    "Assigned roles (" + str(len(role_names)) + "): " + ", ".join(role_names)
                )
        else:
            if not eval_result.get("hasValidEmail"):
                fail_reasons.append(
                    "No valid email address returned for the authenticated user — "
                    "API access may be unauthenticated or the account is invalid"
                )
            if not eval_result.get("hasAssignedRoles"):
                fail_reasons.append(
                    "No roles assigned to the authenticated user — "
                    "a licensed RSC instance should have at least one role configured"
                )
            recommendations.append(
                "Verify that the Rubrik Security Cloud service account has a valid license and at least one role assigned. "
                "Confirm the RSC subscription is active at https://<accountName>.my.rubrik.com."
            )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        input_summary = {
            "authenticatedUserEmail": eval_result.get("authenticatedUserEmail", ""),
            "assignedRoleCount": eval_result.get("assignedRoleCount", 0)
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
