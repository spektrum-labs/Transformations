"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether MFA is registered for the required proportion of users via userRegistrationDetails.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForUsers", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def evaluate(data):
    try:
        users = data.get("value", [])
        if not users:
            return {"isMFAEnforcedForUsers": False, "totalUsers": 0, "mfaRegisteredCount": 0, "scoreInPercentage": 0.0}
        total = len(users)
        mfa_count = 0
        for user in users:
            if user.get("isMfaRegistered", False):
                mfa_count = mfa_count + 1
        score = (mfa_count / total) * 100
        threshold = 90.0
        is_enforced = score >= threshold
        return {
            "isMFAEnforcedForUsers": is_enforced,
            "totalUsers": total,
            "mfaRegisteredCount": mfa_count,
            "scoreInPercentage": round(score, 2)
        }
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("MFA is registered for >= 90% of users")
            pass_reasons.append("MFA registered: " + str(extra_fields.get("mfaRegisteredCount", 0)) + " of " + str(extra_fields.get("totalUsers", 0)) + " users (" + str(extra_fields.get("scoreInPercentage", 0)) + "%)")
        else:
            fail_reasons.append("MFA registration does not meet the 90% threshold")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            fail_reasons.append("MFA registered: " + str(extra_fields.get("mfaRegisteredCount", 0)) + " of " + str(extra_fields.get("totalUsers", 0)) + " users (" + str(extra_fields.get("scoreInPercentage", 0)) + "%)")
            recommendations.append("Enforce MFA registration for all users via Entra ID Conditional Access or Identity Protection policies")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=summary_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
