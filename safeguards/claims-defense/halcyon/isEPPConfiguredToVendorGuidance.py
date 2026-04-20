"""
Transformation: isEPPConfiguredToVendorGuidance
Vendor: Halcyon  |  Category: Claims Defense
Evaluates: Checks that active Halcyon policies conform to vendor-recommended settings
including full-protection mode (not detection-only), anti-tamper service protection
enabled, behavioral engine and pre-execution analysis enabled, and kernel guard
protection enabled. Uses the getPolicies endpoint.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfiguredToVendorGuidance", "vendor": "Halcyon", "category": "Claims Defense"}
        }
    }


def get_bool_flag(policy, keys):
    """
    Walk a list of candidate key names and return the first truthy bool-like value found,
    or None if none of the keys exist in the policy dict.
    """
    for key in keys:
        if key in policy:
            raw = policy[key]
            if raw is None:
                continue
            if isinstance(raw, bool):
                return raw
            if isinstance(raw, int):
                return raw != 0
            sv = str(raw).lower().strip()
            if sv in ["true", "1", "yes", "enabled", "on"]:
                return True
            if sv in ["false", "0", "no", "disabled", "off"]:
                return False
    return None


def evaluate_single_policy(policy):
    """
    Evaluate one policy dict against Halcyon vendor guidance.
    Returns a dict of check results keyed by check name.
    """
    checks = {}

    mode = str(policy.get("mode", "") or policy.get("protectionMode", "") or policy.get("agentMode", "") or "").lower().strip()
    detection_only_indicators = ["detection", "detect", "audit", "passive", "monitor", "readonly", "read-only"]
    is_full_protection = True
    for ind in detection_only_indicators:
        if ind in mode:
            is_full_protection = False
            break
    if mode == "":
        is_full_protection = None
    checks["fullProtectionMode"] = is_full_protection

    tamper_keys = ["antiTamper", "anti_tamper", "tamperProtection", "tamper_protection", "serviceProtection", "service_protection", "antiTamperEnabled", "tamperEnabled"]
    tamper_val = get_bool_flag(policy, tamper_keys)
    checks["antiTamperEnabled"] = tamper_val

    behavioral_keys = ["behavioralEngine", "behavioral_engine", "behavioralAnalysis", "behavioral_analysis", "behaviorEngine", "behaviorAnalysis", "behavioralProtection"]
    behavioral_val = get_bool_flag(policy, behavioral_keys)
    checks["behavioralEngineEnabled"] = behavioral_val

    preexec_keys = ["preExecution", "pre_execution", "preExecutionAnalysis", "pre_execution_analysis", "preExec", "pre_exec", "staticAnalysis", "static_analysis", "preExecutionEnabled"]
    preexec_val = get_bool_flag(policy, preexec_keys)
    checks["preExecutionAnalysisEnabled"] = preexec_val

    kernel_keys = ["kernelGuard", "kernel_guard", "kernelProtection", "kernel_protection", "kernelGuardEnabled", "kernelModeProtection", "kernel_mode_protection"]
    kernel_val = get_bool_flag(policy, kernel_keys)
    checks["kernelGuardEnabled"] = kernel_val

    return checks


def evaluate(data):
    criteriaKey = "isEPPConfiguredToVendorGuidance"
    try:
        policies_raw = data.get("policies", [])
        if policies_raw is None:
            policies_raw = []
        if not isinstance(policies_raw, list):
            policies_raw = []

        total_policies = len(policies_raw)

        if total_policies == 0:
            return {
                criteriaKey: False,
                "totalPolicies": 0,
                "compliantPolicies": 0,
                "nonCompliantPolicies": 0,
                "scoreInPercentage": 0,
                "failedChecks": [],
                "error": "No policies returned from the Halcyon API. Cannot evaluate vendor guidance compliance."
            }

        active_policies = []
        for p in policies_raw:
            if not isinstance(p, dict):
                continue
            enabled = p.get("enabled", None)
            active = p.get("active", None)
            status = str(p.get("status", "") or "").lower().strip()
            is_disabled = False
            if enabled is False:
                is_disabled = True
            if active is False:
                is_disabled = True
            if status in ["disabled", "inactive", "archived"]:
                is_disabled = True
            if not is_disabled:
                active_policies.append(p)

        if len(active_policies) == 0:
            active_policies = policies_raw

        check_names = ["fullProtectionMode", "antiTamperEnabled", "behavioralEngineEnabled", "preExecutionAnalysisEnabled", "kernelGuardEnabled"]

        compliant_count = 0
        non_compliant_count = 0
        all_failed_checks = {}
        policy_results = []

        for p in active_policies:
            policy_name = str(p.get("name", "") or p.get("policyName", "") or "unnamed")
            checks = evaluate_single_policy(p)
            policy_failed = []

            for check_name in check_names:
                check_val = checks.get(check_name, None)
                if check_val is False:
                    policy_failed.append(check_name)
                    if check_name not in all_failed_checks:
                        all_failed_checks[check_name] = []
                    all_failed_checks[check_name].append(policy_name)

            if len(policy_failed) == 0:
                compliant_count = compliant_count + 1
            else:
                non_compliant_count = non_compliant_count + 1

            policy_results.append({"name": policy_name, "failedChecks": policy_failed, "compliant": len(policy_failed) == 0})

        evaluated_count = len(active_policies)
        score = 0
        if evaluated_count > 0:
            score = (compliant_count * 100) // evaluated_count

        result_value = score >= 80

        aggregated_failed = []
        for ck in all_failed_checks:
            aggregated_failed.append(ck + " (affected policies: " + ", ".join(all_failed_checks[ck]) + ")")

        return {
            criteriaKey: result_value,
            "totalPolicies": total_policies,
            "evaluatedPolicies": evaluated_count,
            "compliantPolicies": compliant_count,
            "nonCompliantPolicies": non_compliant_count,
            "scoreInPercentage": score,
            "failedChecks": aggregated_failed,
            "policyResults": policy_results
        }
    except Exception as e:
        return {criteriaKey: False, "error": str(e)}


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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_policies = eval_result.get("totalPolicies", 0)
        evaluated = eval_result.get("evaluatedPolicies", 0)
        compliant = eval_result.get("compliantPolicies", 0)
        non_compliant = eval_result.get("nonCompliantPolicies", 0)
        score = eval_result.get("scoreInPercentage", 0)
        failed_checks = eval_result.get("failedChecks", [])
        policy_results = eval_result.get("policyResults", [])

        if "error" in eval_result:
            fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure at least one active Halcyon policy exists and the API is returning policy configuration data.")
        elif result_value:
            pass_reasons.append("Halcyon policies are configured in accordance with vendor guidance.")
            pass_reasons.append("Compliant policies: " + str(compliant) + " of " + str(evaluated) + " (" + str(score) + "%).")
            pass_reasons.append("Vendor guidance checks: full-protection mode, anti-tamper, behavioral engine, pre-execution analysis, and kernel guard are all enabled.")
        else:
            fail_reasons.append("One or more active Halcyon policies do not conform to vendor-recommended configuration.")
            fail_reasons.append("Compliance score: " + str(score) + "%. Minimum required: 80%.")
            if non_compliant > 0:
                fail_reasons.append(str(non_compliant) + " policy/policies have misconfigured settings.")
            for fc in failed_checks:
                fail_reasons.append("Failed check: " + fc)
            recommendations.append("Enable full-protection mode (not detection-only) on all active Halcyon policies.")
            recommendations.append("Enable anti-tamper / service protection to prevent unauthorized agent disablement.")
            recommendations.append("Enable the behavioral engine and pre-execution analysis for comprehensive ransomware detection.")
            recommendations.append("Enable kernel guard protection to protect against kernel-level attacks.")
            recommendations.append("Review non-compliant policies in the Halcyon console under Settings > Policies.")

        for pr in policy_results:
            pname = pr.get("name", "unnamed")
            pstatus = "COMPLIANT" if pr.get("compliant", False) else "NON-COMPLIANT"
            pfailed = pr.get("failedChecks", [])
            if pfailed:
                additional_findings.append("Policy '" + pname + "': " + pstatus + " - failed: " + ", ".join(pfailed))
            else:
                additional_findings.append("Policy '" + pname + "': " + pstatus)

        additional_findings.append("Total policies: " + str(total_policies) + ", Evaluated (active): " + str(evaluated))

        result_dict = {criteriaKey: result_value}
        result_dict["totalPolicies"] = total_policies
        result_dict["evaluatedPolicies"] = evaluated
        result_dict["compliantPolicies"] = compliant
        result_dict["nonCompliantPolicies"] = non_compliant
        result_dict["scoreInPercentage"] = score

        summary_dict = {
            "totalPolicies": total_policies,
            "evaluatedPolicies": evaluated,
            "compliantPolicies": compliant,
            "scoreInPercentage": score
        }

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=summary_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
