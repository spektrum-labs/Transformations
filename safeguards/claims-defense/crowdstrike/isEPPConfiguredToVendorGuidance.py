"""
Transformation: isEPPConfiguredToVendorGuidance
Vendor: Crowdstrike  |  Category: claims-defense
Evaluates: Verify that active Prevention Policies have key protection classes enabled per
CrowdStrike vendor guidance, inspecting settings.classes for machine learning (ML), exploit
prevention, behavioral analysis, and process blocking capabilities all in 'ENABLED' or
'AGGRESSIVE' mode.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfiguredToVendorGuidance", "vendor": "Crowdstrike", "category": "claims-defense"}
        }
    }


REQUIRED_CLASS_IDS = [
    "MACHINE_LEARNING",
    "EXPLOIT_MITIGATION",
    "BEHAVIORAL_ANALYSIS",
    "PROCESS_BLOCKING"
]

ACCEPTABLE_MODES = ["ENABLED", "AGGRESSIVE"]


def check_policy_classes(policy):
    settings = policy.get("prevention_settings", policy.get("settings", {}))
    if not isinstance(settings, dict):
        settings = {}
    classes = settings.get("classes", [])
    if not isinstance(classes, list):
        classes = []
    found_ids = {}
    for cls in classes:
        if not isinstance(cls, dict):
            continue
        class_id = cls.get("id", "")
        mode = cls.get("prevention_mode", cls.get("mode", "DISABLED"))
        if not isinstance(mode, str):
            mode = "DISABLED"
        found_ids[class_id] = mode.upper()
    missing = []
    non_compliant = []
    compliant = []
    for req_id in REQUIRED_CLASS_IDS:
        if req_id not in found_ids:
            missing.append(req_id)
        elif found_ids[req_id] not in ACCEPTABLE_MODES:
            non_compliant.append(req_id + " (mode: " + found_ids[req_id] + ")")
        else:
            compliant.append(req_id + " (mode: " + found_ids[req_id] + ")")
    is_compliant = len(missing) == 0 and len(non_compliant) == 0
    return is_compliant, compliant, non_compliant, missing


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not isinstance(resources, list):
            resources = []
        total_policies = len(resources)
        enabled_policies = [p for p in resources if isinstance(p, dict) and p.get("enabled", False)]
        if len(enabled_policies) == 0:
            return {
                "isEPPConfiguredToVendorGuidance": False,
                "totalPolicies": total_policies,
                "enabledPoliciesCount": 0,
                "compliantPoliciesCount": 0,
                "nonCompliantPoliciesCount": 0,
                "complianceDetails": [],
                "error": "No enabled Prevention Policies found to evaluate vendor guidance compliance."
            }
        compliant_policies = []
        non_compliant_policies = []
        compliance_details = []
        for policy in enabled_policies:
            policy_name = policy.get("name", "Unknown")
            policy_id = policy.get("id", "")
            label = policy_name + " (" + policy_id + ")"
            is_compliant, compliant_classes, non_compliant_classes, missing_classes = check_policy_classes(policy)
            detail = {
                "policy": label,
                "compliant": is_compliant,
                "compliantClasses": compliant_classes,
                "nonCompliantClasses": non_compliant_classes,
                "missingClasses": missing_classes
            }
            compliance_details.append(detail)
            if is_compliant:
                compliant_policies.append(label)
            else:
                non_compliant_policies.append(label)
        all_compliant = len(non_compliant_policies) == 0 and len(compliant_policies) > 0
        return {
            "isEPPConfiguredToVendorGuidance": all_compliant,
            "totalPolicies": total_policies,
            "enabledPoliciesCount": len(enabled_policies),
            "compliantPoliciesCount": len(compliant_policies),
            "nonCompliantPoliciesCount": len(non_compliant_policies),
            "complianceDetails": compliance_details
        }
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
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        extra_fields["totalPolicies"] = eval_result.get("totalPolicies", 0)
        extra_fields["enabledPoliciesCount"] = eval_result.get("enabledPoliciesCount", 0)
        extra_fields["compliantPoliciesCount"] = eval_result.get("compliantPoliciesCount", 0)
        extra_fields["nonCompliantPoliciesCount"] = eval_result.get("nonCompliantPoliciesCount", 0)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("All enabled Prevention Policies are configured per CrowdStrike vendor guidance with required protection classes active.")
            pass_reasons.append("Compliant policies: " + str(eval_result.get("compliantPoliciesCount", 0)) + " of " + str(eval_result.get("enabledPoliciesCount", 0)) + " enabled policies.")
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("One or more enabled Prevention Policies do not meet CrowdStrike vendor guidance for required protection class configuration.")
                fail_reasons.append("Non-compliant policies: " + str(eval_result.get("nonCompliantPoliciesCount", 0)) + " of " + str(eval_result.get("enabledPoliciesCount", 0)) + " enabled policies.")
            recommendations.append("Enable MACHINE_LEARNING, EXPLOIT_MITIGATION, BEHAVIORAL_ANALYSIS, and PROCESS_BLOCKING classes in ENABLED or AGGRESSIVE mode for all active Prevention Policies.")
            recommendations.append("Navigate to Endpoint Security > Prevention Policies in the Falcon console, select each active policy, and review the protection class settings.")
        compliance_details = eval_result.get("complianceDetails", [])
        for detail in compliance_details:
            if not isinstance(detail, dict):
                continue
            policy_label = detail.get("policy", "Unknown")
            if detail.get("compliant", False):
                additional_findings.append("COMPLIANT: " + policy_label)
            else:
                nc_classes = detail.get("nonCompliantClasses", [])
                ms_classes = detail.get("missingClasses", [])
                finding = "NON-COMPLIANT: " + policy_label
                if nc_classes:
                    finding = finding + " | Insufficient mode: " + ", ".join(nc_classes)
                if ms_classes:
                    finding = finding + " | Missing classes: " + ", ".join(ms_classes)
                additional_findings.append(finding)
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
