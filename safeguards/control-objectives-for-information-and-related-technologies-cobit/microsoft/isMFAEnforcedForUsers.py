"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Checks whether at least one enabled Conditional Access policy targeting all users
has grantControls.builtInControls containing 'mfa', confirming MFA is enforced
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForUsers", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        policies = data.get("value", [])
        if not policies:
            return {
                "isMFAEnforcedForUsers": False,
                "reason": "No Conditional Access policies found",
                "totalPolicies": 0,
                "mfaPoliciesCount": 0,
                "mfaPolicyNames": []
            }
        mfa_policy_names = []
        total = len(policies)
        for policy in policies:
            state = policy.get("state", "")
            if state != "enabled":
                continue
            conditions = policy.get("conditions", {})
            users = conditions.get("users", {})
            include_users = users.get("includeUsers", [])
            targets_all = "All" in include_users
            grant_controls = policy.get("grantControls", {})
            if grant_controls is None:
                grant_controls = {}
            built_in = grant_controls.get("builtInControls", [])
            if built_in is None:
                built_in = []
            has_mfa = "mfa" in built_in
            if targets_all and has_mfa:
                mfa_policy_names.append(policy.get("displayName", "Unnamed"))
        mfa_enforced = len(mfa_policy_names) > 0
        return {
            "isMFAEnforcedForUsers": mfa_enforced,
            "totalPolicies": total,
            "mfaPoliciesCount": len(mfa_policy_names),
            "mfaPolicyNames": mfa_policy_names
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
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error" and k != "reason":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed: MFA-enforcing Conditional Access policy targeting all users found")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append(criteriaKey + " check failed: No enabled Conditional Access policy requiring MFA for all users found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if "reason" in eval_result:
                fail_reasons.append(eval_result["reason"])
            recommendations.append("Create an enabled Conditional Access policy that targets all users and requires MFA as a grant control in Microsoft Entra ID")
        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=result_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
