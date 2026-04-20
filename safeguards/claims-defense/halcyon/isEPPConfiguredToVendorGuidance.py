"""
Transformation: isEPPConfiguredToVendorGuidance
Vendor: Halcyon  |  Category: claims-defense
Evaluates: Validates that Halcyon EPP policies are configured in accordance with Halcyon
vendor best-practice guidance. Inspects the /v1/policies response to confirm key policy
settings -- pre-execution prevention, behavioral monitoring, anti-tamper, and resiliency
engine -- are all enabled as recommended by Halcyon.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
                "transformationId": "isEPPConfiguredToVendorGuidance",
                "vendor": "Halcyon",
                "category": "claims-defense"
            }
        }
    }


def policy_is_active(policy):
    if policy.get("enabled") is True:
        return True
    if policy.get("active") is True:
        return True
    if policy.get("isActive") is True:
        return True
    status_raw = policy.get("status", "")
    if status_raw:
        status_lower = str(status_raw).lower()
        if "active" in status_lower or "enabled" in status_lower:
            return True
    if "enabled" not in policy and "active" not in policy and "isActive" not in policy and "status" not in policy:
        return True
    return False


def resolve_setting(policy, variants):
    for name in variants:
        val = policy.get(name)
        if val is not None:
            return val
    settings_obj = policy.get("settings", policy.get("configuration", policy.get("config", None)))
    if isinstance(settings_obj, dict):
        for name in variants:
            val = settings_obj.get(name)
            if val is not None:
                return val
    return None


def policy_meets_vendor_guidance(policy):
    pre_exec_variants = ["preExecutionPrevention", "pre_execution_prevention", "preExecution", "preExecutionBlocking", "preventExecution"]
    behavioral_variants = ["behavioralMonitoring", "behavioral_monitoring", "behaviouralMonitoring", "behaviorMonitoring", "behavioralEngine", "behaviouralEngine"]
    anti_tamper_variants = ["antiTamper", "anti_tamper", "tamperProtection", "tamper_protection", "tamperPrevention", "antiTamperEnabled"]
    resiliency_variants = ["resiliencyEngine", "resiliency_engine", "resiliency", "resilience", "resilienceEngine", "resiliencyEnabled"]

    required_groups = [pre_exec_variants, behavioral_variants, anti_tamper_variants, resiliency_variants]
    required_names = ["preExecutionPrevention", "behavioralMonitoring", "antiTamper", "resiliencyEngine"]

    missing = []
    disabled = []

    idx = 0
    for variants in required_groups:
        val = resolve_setting(policy, variants)
        if val is None:
            missing.append(required_names[idx])
        elif val is False or val == 0 or val == "disabled" or val == "false":
            disabled.append(required_names[idx])
        idx = idx + 1

    return missing, disabled


def evaluate(data):
    try:
        policies = data.get("data", [])
        if not isinstance(policies, list):
            policies = []

        total_policies = len(policies)

        if total_policies == 0:
            return {
                "isEPPConfiguredToVendorGuidance": False,
                "totalPolicies": 0,
                "activePolicies": 0,
                "compliantPolicies": 0,
                "nonCompliantPolicies": 0,
                "evaluationNote": "No policies found in response"
            }

        active_policies = []
        for policy in policies:
            if policy_is_active(policy):
                active_policies.append(policy)

        active_count = len(active_policies)

        if active_count == 0:
            return {
                "isEPPConfiguredToVendorGuidance": False,
                "totalPolicies": total_policies,
                "activePolicies": 0,
                "compliantPolicies": 0,
                "nonCompliantPolicies": 0,
                "evaluationNote": "No active policies found"
            }

        compliant_count = 0
        non_compliant_count = 0
        non_compliant_details = []

        for policy in active_policies:
            policy_name = policy.get("name", policy.get("policyName", policy.get("id", "unnamed")))
            missing, disabled = policy_meets_vendor_guidance(policy)
            if missing or disabled:
                non_compliant_count = non_compliant_count + 1
                detail = str(policy_name)
                issues = []
                if missing:
                    issues.append("missing: " + ", ".join(missing))
                if disabled:
                    issues.append("disabled: " + ", ".join(disabled))
                detail = detail + " (" + "; ".join(issues) + ")"
                non_compliant_details.append(detail)
            else:
                compliant_count = compliant_count + 1

        all_compliant = non_compliant_count == 0

        return {
            "isEPPConfiguredToVendorGuidance": all_compliant,
            "totalPolicies": total_policies,
            "activePolicies": active_count,
            "compliantPolicies": compliant_count,
            "nonCompliantPolicies": non_compliant_count,
            "nonCompliantDetails": non_compliant_details
        }

    except Exception as e:
        return {"isEPPConfiguredToVendorGuidance": False, "evaluationNote": str(e)}


def transform(input):
    criteriaKey = "isEPPConfiguredToVendorGuidance"
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
            if k != criteriaKey and k != "evaluationNote":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("All active Halcyon EPP policies are configured in accordance with vendor best-practice guidance.")
            pass_reasons.append(
                "Compliant policies: " + str(eval_result.get("compliantPolicies", 0)) +
                " of " + str(eval_result.get("activePolicies", 0)) + " active policies."
            )
            pass_reasons.append("All required settings are enabled: preExecutionPrevention, behavioralMonitoring, antiTamper, resiliencyEngine.")
        else:
            note = eval_result.get("evaluationNote", "")
            if note:
                fail_reasons.append(note)
            else:
                fail_reasons.append("One or more active Halcyon EPP policies are not configured to vendor guidance.")
                fail_reasons.append(
                    "Non-compliant policies: " + str(eval_result.get("nonCompliantPolicies", 0)) +
                    " of " + str(eval_result.get("activePolicies", 0)) + " active policies."
                )
                non_compliant_details = eval_result.get("nonCompliantDetails", [])
                for detail in non_compliant_details:
                    additional_findings.append(detail)
            recommendations.append(
                "Review all active Halcyon EPP policies and ensure preExecutionPrevention, behavioralMonitoring, antiTamper, and resiliencyEngine are all enabled."
            )
            recommendations.append(
                "Consult Halcyon vendor documentation to align policy configuration with recommended best-practice baseline settings."
            )

        final_result = {criteriaKey: result_value}
        for k in extra_fields:
            final_result[k] = extra_fields[k]

        input_summary = {
            "totalPolicies": eval_result.get("totalPolicies", 0),
            "activePolicies": eval_result.get("activePolicies", 0),
            "compliantPolicies": eval_result.get("compliantPolicies", 0)
        }

        return create_response(
            result=final_result,
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
