"""
Transformation: isEPPConfiguredToVendorGuidance
Vendor: Halcyon  |  Category: epp
Evaluates: Validates that Halcyon policy groups are configured in line with vendor-recommended
settings, including blocking mode enabled and prevention engines active, rather than left in
default learning or passive modes.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfiguredToVendorGuidance", "vendor": "Halcyon", "category": "epp"}
        }
    }


NON_COMPLIANT_MODES = ["learning", "audit", "passive", "monitor", "observe", "detection", "detect"]
COMPLIANT_MODES = ["blocking", "block", "prevent", "prevention", "protect", "active", "enforce"]


def get_policy_mode(policy):
    mode = policy.get("mode", "") or policy.get("protection_mode", "") or policy.get("protectionMode", "") or policy.get("enforcement_mode", "") or policy.get("enforcementMode", "")
    if isinstance(mode, str):
        return mode.lower()
    return ""


def is_policy_active(policy):
    status = policy.get("status", "") or policy.get("state", "")
    if isinstance(status, str) and status.lower() in ["active", "enabled", "on"]:
        return True
    enabled = policy.get("enabled", None)
    if enabled is True:
        return True
    return False


def prevention_engines_active(policy):
    engines = policy.get("prevention_engines", None) or policy.get("preventionEngines", None)
    if engines is None:
        return None
    if isinstance(engines, bool):
        return engines
    if isinstance(engines, dict):
        values = [engines[k] for k in engines]
        true_count = len([v for v in values if v is True or v == "enabled" or v == "active"])
        return true_count > 0
    if isinstance(engines, list):
        active = [e for e in engines if e.get("enabled", False) is True or e.get("status", "") in ["active", "enabled"]]
        return len(active) > 0
    return None


def check_policy_compliant(policy):
    mode = get_policy_mode(policy)
    mode_compliant = True
    mode_finding = ""
    if mode in NON_COMPLIANT_MODES:
        mode_compliant = False
        mode_finding = "policy mode is '" + mode + "' (non-compliant)"
    elif mode in COMPLIANT_MODES:
        mode_compliant = True
    elif mode == "":
        mode_compliant = True

    engines_result = prevention_engines_active(policy)
    engines_compliant = True
    engines_finding = ""
    if engines_result is False:
        engines_compliant = False
        engines_finding = "prevention engines are disabled"

    compliant = mode_compliant and engines_compliant
    findings = []
    if mode_finding:
        findings.append(mode_finding)
    if engines_finding:
        findings.append(engines_finding)
    return compliant, findings


def evaluate(data):
    try:
        policies_raw = data.get("data", [])
        if not isinstance(policies_raw, list):
            policies_raw = []

        if len(policies_raw) == 0:
            return {
                "isEPPConfiguredToVendorGuidance": False,
                "totalPolicies": 0,
                "activePolicies": 0,
                "compliantPolicies": 0,
                "nonCompliantPolicies": 0,
                "scoreInPercentage": 0,
                "error": "No policy data returned from API"
            }

        active_policies = [p for p in policies_raw if is_policy_active(p)]
        total_active = len(active_policies)

        if total_active == 0:
            return {
                "isEPPConfiguredToVendorGuidance": False,
                "totalPolicies": len(policies_raw),
                "activePolicies": 0,
                "compliantPolicies": 0,
                "nonCompliantPolicies": 0,
                "scoreInPercentage": 0,
                "error": "No active policies found"
            }

        compliant_count = 0
        non_compliant_details = []
        for policy in active_policies:
            compliant, findings = check_policy_compliant(policy)
            if compliant:
                compliant_count = compliant_count + 1
            else:
                policy_name = policy.get("name", policy.get("id", "unknown"))
                non_compliant_details.append(str(policy_name) + ": " + "; ".join(findings))

        score = (compliant_count * 100) / total_active
        passed = score >= 90

        result = {
            "isEPPConfiguredToVendorGuidance": passed,
            "totalPolicies": len(policies_raw),
            "activePolicies": total_active,
            "compliantPolicies": compliant_count,
            "nonCompliantPolicies": total_active - compliant_count,
            "scoreInPercentage": score
        }
        if non_compliant_details:
            result["nonCompliantPolicyDetails"] = non_compliant_details
        return result
    except Exception as e:
        return {"isEPPConfiguredToVendorGuidance": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPConfiguredToVendorGuidance"
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
        score = eval_result.get("scoreInPercentage", 0)
        compliant_count = eval_result.get("compliantPolicies", 0)
        active_count = eval_result.get("activePolicies", 0)
        non_compliant_details = eval_result.get("nonCompliantPolicyDetails", [])
        if result_value:
            pass_reasons.append("Halcyon policies are configured in line with vendor guidance (" + str(compliant_count) + "/" + str(active_count) + " active policies compliant)")
            pass_reasons.append("Compliance score: " + str(round(score, 1)) + "%")
        else:
            fail_reasons.append("One or more Halcyon policies deviate from vendor-recommended configuration (" + str(compliant_count) + "/" + str(active_count) + " compliant, score: " + str(round(score, 1)) + "%)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            for detail in non_compliant_details:
                additional_findings.append("Non-compliant policy: " + str(detail))
            recommendations.append("Enable blocking/prevention mode on all active Halcyon policies; avoid leaving policies in learning, audit, or passive modes")
            recommendations.append("Ensure prevention engines are active across all policy groups as recommended by Halcyon vendor guidance")
            recommendations.append("Review each non-compliant policy and update settings to align with Halcyon hardening recommendations")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPolicies": eval_result.get("totalPolicies", 0), "activePolicies": active_count, "compliantPolicies": compliant_count, "scoreInPercentage": score}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
