"""
Transformation: UniquePasswordsUsed
Vendor: Okta  |  Category: cis-controls-v8-ig1
Evaluates: Whether at least one active PASSWORD policy enforces password history (count > 0),
           ensuring users cannot reuse recent passwords.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "UniquePasswordsUsed", "vendor": "Okta", "category": "cis-controls-v8-ig1"}
        }
    }


def get_policies_by_type(data, policy_type):
    policies = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("type") == policy_type:
                policies.append(item)
    return policies


def evaluate(data):
    try:
        password_policies = get_policies_by_type(data, "PASSWORD")
        active_policies = [p for p in password_policies if p.get("status") == "ACTIVE"]
        total_policies = len(password_policies)
        active_count = len(active_policies)

        enforcing_history = []
        not_enforcing = []

        for policy in active_policies:
            name = policy.get("name", "Unnamed")
            settings = policy.get("settings", {})
            password_settings = settings.get("password", {})
            history = password_settings.get("history", {})
            history_count = history.get("count", 0)
            if history_count is None:
                history_count = 0
            if history_count > 0:
                enforcing_history.append(name + " (history count: " + str(history_count) + ")")
            else:
                not_enforcing.append(name)

        passes = len(enforcing_history) > 0

        return {
            "UniquePasswordsUsed": passes,
            "totalPasswordPolicies": total_policies,
            "activePoliciesCount": active_count,
            "policiesEnforcingHistory": len(enforcing_history),
            "policiesEnforcingHistoryNames": enforcing_history,
            "policiesNotEnforcingHistory": not_enforcing
        }
    except Exception as e:
        return {"UniquePasswordsUsed": False, "error": str(e)}


def transform(input):
    criteriaKey = "UniquePasswordsUsed"
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
        additional_findings = []

        if result_value:
            pass_reasons.append("At least one active PASSWORD policy enforces password history (non-reuse).")
            for name in extra_fields.get("policiesEnforcingHistoryNames", []):
                pass_reasons.append("Enforcing policy: " + name)
        else:
            fail_reasons.append("No active PASSWORD policy enforces password history. Users may reuse previous passwords.")
            for name in extra_fields.get("policiesNotEnforcingHistory", []):
                additional_findings.append("Policy with no history enforcement: " + name)
            recommendations.append("Configure password history count > 0 on at least one active PASSWORD policy in Okta.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPasswordPolicies": extra_fields.get("totalPasswordPolicies", 0),
                "activePoliciesCount": extra_fields.get("activePoliciesCount", 0),
                "policiesEnforcingHistory": extra_fields.get("policiesEnforcingHistory", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
