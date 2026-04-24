"""
Transformation: isEPPEnabledForCriticalSystems
Vendor: Crowdstrike  |  Category: epp
Evaluates: Check that at least one prevention policy is enabled (enabled: true) and has host
groups assigned (groups array is non-empty), indicating EPP coverage is deployed to systems
in the environment. Policies with no assigned groups or that are disabled do not count.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabledForCriticalSystems", "vendor": "Crowdstrike", "category": "epp"}
        }
    }


def safe_list(val):
    return val if isinstance(val, list) else []


def evaluate(data):
    try:
        resources = None

        # Try method-keyed merged format
        if isinstance(data, dict):
            gpp = data.get("getPreventionPolicies", None)
            if isinstance(gpp, dict):
                resources = gpp.get("resources", None)

        # Fall back to flat top-level format
        if resources is None and isinstance(data, dict):
            resources = data.get("resources", None)

        if resources is None:
            return {
                "isEPPEnabledForCriticalSystems": None,
                "error": "required fields missing from API response: resources (getPreventionPolicies)"
            }

        policies = safe_list(resources)
        total_policies = len(policies)

        if total_policies == 0:
            return {
                "isEPPEnabledForCriticalSystems": False,
                "totalPolicies": 0,
                "enabledPoliciesWithGroups": 0
            }

        enabled_with_groups = 0
        enabled_no_groups = 0
        disabled_count = 0
        additional = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            raw_enabled = policy.get("enabled", False)
            if isinstance(raw_enabled, str):
                is_enabled = raw_enabled.lower() in ("1", "true", "yes")
            else:
                is_enabled = bool(raw_enabled)

            groups = safe_list(policy.get("groups", []))
            has_groups = len(groups) > 0
            name = policy.get("name", "Unknown")

            if not is_enabled:
                disabled_count = disabled_count + 1
            elif is_enabled and has_groups:
                enabled_with_groups = enabled_with_groups + 1
                additional.append("Policy '" + name + "' is enabled with " + str(len(groups)) + " group(s) assigned")
            elif is_enabled and not has_groups:
                enabled_no_groups = enabled_no_groups + 1

        is_epp_enabled = enabled_with_groups > 0

        return {
            "isEPPEnabledForCriticalSystems": is_epp_enabled,
            "totalPolicies": total_policies,
            "enabledPoliciesWithGroups": enabled_with_groups,
            "enabledPoliciesWithoutGroups": enabled_no_groups,
            "disabledPolicies": disabled_count,
            "additionalFindings": additional
        }
    except Exception as e:
        return {"isEPPEnabledForCriticalSystems": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPEnabledForCriticalSystems"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        additional_findings = eval_result.get("additionalFindings", [])
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error" and k != "additionalFindings"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value is True:
            pass_reasons.append(criteriaKey + " check passed")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields.get(k)))
        elif result_value is None:
            fail_reasons.append(criteriaKey + " could not be evaluated: insufficient data in API response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the getPreventionPolicies API endpoint returns a non-empty resources array")
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            for k in extra_fields:
                fail_reasons.append(k + ": " + str(extra_fields.get(k)))
            recommendations.append("Ensure at least one prevention policy is enabled and has host groups assigned in CrowdStrike Falcon")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields.get(k)

        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields.get(k)

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
