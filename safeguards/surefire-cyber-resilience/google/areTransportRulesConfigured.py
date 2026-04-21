"""
Transformation: areTransportRulesConfigured
Vendor: Google  |  Category: Email Security
Evaluates: Whether at least one active Gmail routing/transport rule is configured
           for the Google Workspace domain via gmail.routing policies.
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
                "transformationId": "areTransportRulesConfigured",
                "vendor": "Google",
                "category": "Email Security"
            }
        }
    }


def policy_is_active(policy):
    """Return True if a policy dict has an active/enabled status or no status field (presence implies active)."""
    status = policy.get("status", "")
    if not status:
        return True
    return status.lower() in ["active", "enabled", "enforced"]


def evaluate(data):
    """Iterate gmail.routing policies and return True if at least one active rule is found."""
    try:
        policies = data.get("policies", [])
        if not isinstance(policies, list):
            policies = []

        routing_policies_found = 0
        active_routing_rules = 0

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            setting = policy.get("setting", {})
            if not isinstance(setting, dict):
                setting = {}

            setting_type = setting.get("type", "")
            policy_name = policy.get("name", "")

            is_routing = (
                setting_type == "gmail.routing" or
                "routing" in setting_type.lower() or
                "routing" in policy_name.lower() or
                "transport" in policy_name.lower()
            )

            if not is_routing:
                continue

            routing_policies_found = routing_policies_found + 1

            if policy_is_active(policy):
                active_routing_rules = active_routing_rules + 1

        result = active_routing_rules > 0

        return {
            "areTransportRulesConfigured": result,
            "routingPoliciesFound": routing_policies_found,
            "activeRoutingRulesCount": active_routing_rules,
        }
    except Exception as e:
        return {"areTransportRulesConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "areTransportRulesConfigured"
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
            pass_reasons.append("At least one active Gmail routing/transport rule is configured")
            pass_reasons.append("activeRoutingRulesCount: " + str(extra_fields.get("activeRoutingRulesCount", 0)))
        else:
            fail_reasons.append("No active Gmail routing/transport rules were found in gmail.routing policies")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Configure Gmail routing rules in Google Workspace Admin Console under "
                "Apps > Google Workspace > Gmail > Routing"
            )

        full_result = {}
        full_result[criteriaKey] = result_value
        for k in extra_fields:
            full_result[k] = extra_fields[k]

        input_sum = {}
        input_sum[criteriaKey] = result_value
        for k in extra_fields:
            input_sum[k] = extra_fields[k]

        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_sum
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
