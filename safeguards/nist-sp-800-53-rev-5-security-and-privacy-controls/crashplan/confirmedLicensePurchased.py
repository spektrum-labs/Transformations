"""
Transformation: confirmedLicensePurchased
Vendor: CrashPlan  |  Category: nist-sp-800-53-rev-5-security-and-privacy-controls
Evaluates: Whether a valid CrashPlan license has been purchased by verifying the API returns
active users. A successful authenticated response with one or more active users confirms
the organization holds an active CrashPlan subscription with API access enabled.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
                "vendor": "CrashPlan",
                "category": "nist-sp-800-53-rev-5-security-and-privacy-controls"
            }
        }
    }


def evaluate(data):
    try:
        users = data.get("users", [])
        if not isinstance(users, list):
            users = []

        total_users = len(users)
        active_count = 0
        for user in users:
            if user.get("active", False):
                active_count = active_count + 1

        has_license = active_count > 0

        return {
            "confirmedLicensePurchased": has_license,
            "totalUsers": total_users,
            "activeUsers": active_count
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
        total = eval_result.get("totalUsers", 0)
        active = eval_result.get("activeUsers", 0)
        if result_value:
            pass_reasons.append("A valid CrashPlan license is confirmed: the API returned active users.")
            pass_reasons.append(
                str(active) + " active user(s) found out of " + str(total) + " total users."
            )
            pass_reasons.append(
                "Successful authenticated API access with active user data confirms an active CrashPlan subscription."
            )
        else:
            fail_reasons.append("Could not confirm a valid CrashPlan license: no active users returned by the API.")
            fail_reasons.append(
                str(active) + " active user(s) found out of " + str(total) + " total users."
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Verify that the CrashPlan account has an active subscription and that the API client credentials are correct."
            )
            recommendations.append(
                "Confirm that the organization has active users provisioned in the CrashPlan console."
            )
        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]
        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalUsers": total, "activeUsers": active}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
