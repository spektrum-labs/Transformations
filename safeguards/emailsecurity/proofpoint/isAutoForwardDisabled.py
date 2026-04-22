"""
Transformation: isAutoForwardDisabled
Vendor: Proofpoint  |  Category: emailsecurity
Evaluates: Inspect the organization's filter policies to verify there is no active outbound
auto-forwarding rule, or that auto-forward is explicitly blocked by policy (getFilterPolicies).
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
                "transformationId": "isAutoForwardDisabled",
                "vendor": "Proofpoint",
                "category": "emailsecurity"
            }
        }
    }


def evaluate(data):
    try:
        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            policies = data.get("policies", data.get("filter_policies", []))
            if not isinstance(policies, list):
                policies = []

        total_policies = len(policies)
        auto_forward_block_found = False
        active_forward_rules = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            ptype = str(policy.get("type", "")).lower()
            pname = str(policy.get("name", "")).lower()
            action = str(policy.get("action", "")).lower()
            enabled = policy.get("enabled", policy.get("active", False))
            direction = str(policy.get("direction", "")).lower()

            is_outbound = (direction == "outbound" or direction == "")

            is_forward_related = (
                "forward" in pname or
                "auto_forward" in ptype or
                "autoforward" in ptype or
                "forward" in ptype
            )

            is_block_action = ("block" in action or "deny" in action or "reject" in action)

            if is_forward_related and is_block_action and bool(enabled) and is_outbound:
                auto_forward_block_found = True

            if is_forward_related and not is_block_action and bool(enabled):
                active_forward_rules.append(policy.get("name", "unnamed"))

        is_disabled = auto_forward_block_found or (len(active_forward_rules) == 0)

        return {
            "isAutoForwardDisabled": is_disabled,
            "autoForwardBlockPolicyFound": auto_forward_block_found,
            "activeForwardingRulesCount": len(active_forward_rules),
            "totalPoliciesChecked": total_policies
        }
    except Exception as e:
        return {"isAutoForwardDisabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAutoForwardDisabled"
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
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Auto-forwarding is disabled or blocked by filter policy")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("Active auto-forwarding rules were found without a blocking policy")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Create an outbound filter policy in Proofpoint Essentials to block automatic email forwarding"
            )
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
