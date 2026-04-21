"""
Transformation: isEPPEnabledForCriticalSystems
Vendor: Crowdstrike  |  Category: claims-defense
Evaluates: Verify that enabled Prevention Policies (enabled: true) have assigned host groups
(groups array non-empty), ensuring EPP coverage is deployed to host groups that include
critical systems.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabledForCriticalSystems", "vendor": "Crowdstrike", "category": "claims-defense"}
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not isinstance(resources, list):
            resources = []
        total_policies = len(resources)
        enabled_with_groups = []
        enabled_without_groups = []
        disabled_policies = []
        for policy in resources:
            if not isinstance(policy, dict):
                continue
            policy_name = policy.get("name", "Unknown")
            policy_id = policy.get("id", "")
            label = policy_name + " (" + policy_id + ")"
            is_enabled = policy.get("enabled", False)
            if not is_enabled:
                disabled_policies.append(label)
                continue
            groups = policy.get("groups", [])
            if not isinstance(groups, list):
                groups = []
            if len(groups) > 0:
                group_names = []
                for g in groups:
                    if isinstance(g, dict):
                        group_names.append(g.get("name", g.get("id", "Unknown")))
                    else:
                        group_names.append(str(g))
                enabled_with_groups.append(label + " [groups: " + ", ".join(group_names) + "]")
            else:
                enabled_without_groups.append(label)
        has_enabled_with_groups = len(enabled_with_groups) > 0
        return {
            "isEPPEnabledForCriticalSystems": has_enabled_with_groups,
            "totalPolicies": total_policies,
            "enabledPoliciesWithGroupsCount": len(enabled_with_groups),
            "enabledPoliciesWithoutGroupsCount": len(enabled_without_groups),
            "disabledPoliciesCount": len(disabled_policies),
            "enabledPoliciesWithGroups": enabled_with_groups,
            "enabledPoliciesWithoutGroups": enabled_without_groups
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
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        extra_fields["totalPolicies"] = eval_result.get("totalPolicies", 0)
        extra_fields["enabledPoliciesWithGroupsCount"] = eval_result.get("enabledPoliciesWithGroupsCount", 0)
        extra_fields["enabledPoliciesWithoutGroupsCount"] = eval_result.get("enabledPoliciesWithoutGroupsCount", 0)
        extra_fields["disabledPoliciesCount"] = eval_result.get("disabledPoliciesCount", 0)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("At least one enabled Prevention Policy has host groups assigned, ensuring EPP coverage extends to critical systems.")
            pass_reasons.append("Enabled policies with host groups: " + str(eval_result.get("enabledPoliciesWithGroupsCount", 0)))
            groups_list = eval_result.get("enabledPoliciesWithGroups", [])
            if groups_list:
                additional_findings.append("Policies with host group assignments: " + "; ".join(groups_list))
        else:
            fail_reasons.append("No enabled Prevention Policies have host groups assigned. EPP coverage is not confirmed for critical systems.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Assign host groups to enabled Prevention Policies in the CrowdStrike Falcon console.")
            recommendations.append("Ensure host groups are configured to include critical systems (servers, endpoints with sensitive data).")
            recommendations.append("Navigate to Endpoint Security > Prevention Policies, select a policy, and add host group assignments.")
        no_group_list = eval_result.get("enabledPoliciesWithoutGroups", [])
        if no_group_list:
            additional_findings.append("Enabled policies without host group assignments: " + ", ".join(no_group_list))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
