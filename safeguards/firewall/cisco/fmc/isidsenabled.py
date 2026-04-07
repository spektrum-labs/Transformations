"""
Transformation: isIDSEnabled
Vendor: Cisco FMC  |  Category: Firewall
Evaluates: Whether Intrusion Detection System (IDS) is active on the firewall.

Data source: FMC REST API
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/intrusionpolicies

IDS is enabled when:
  1. At least one intrusion policy exists in FMC
  2. Intrusion policies are in either DETECTION or PREVENTION mode
     (both provide detection capability; PREVENTION additionally blocks)

FMC intrusion policies provide IDS by default — any configured intrusion
policy is performing detection. The inspectionMode field determines whether
it also prevents (blocks) threats, but detection is always active.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isIDSEnabled", "vendor": "Cisco FMC", "category": "Firewall"}
        }
    }


def extract_intrusion_policies(data):
    """Extract intrusion policies from the getIntrusionPolicies response."""
    if isinstance(data, list):
        return [p for p in data if isinstance(p, dict)]
    if not isinstance(data, dict):
        return []
    items = data.get("items", [])
    if isinstance(items, list) and items:
        return [p for p in items if isinstance(p, dict)]
    if "id" in data and ("type" in data or "name" in data):
        return [data]
    return []


def evaluate(data):
    """Evaluate whether IDS is active by checking for intrusion policies."""
    try:
        policies = extract_intrusion_policies(data)

        if not policies:
            return {"isIDSEnabled": False, "error": "No intrusion policies found in FMC"}

        detection_policies = []
        prevention_policies = []

        for policy in policies:
            name = policy.get("name", "Unknown")
            mode = (policy.get("inspectionMode", "") or "").upper()
            policy_info = {
                "name": name,
                "id": policy.get("id", ""),
                "inspectionMode": mode or "UNKNOWN"
            }
            if mode == "PREVENTION":
                prevention_policies.append(policy_info)
            else:
                detection_policies.append(policy_info)

        all_policy_names = [p["name"] for p in detection_policies + prevention_policies]

        findings = []
        findings.append(f"{len(policies)} intrusion policy/policies configured in FMC")
        if detection_policies:
            names = [p["name"] for p in detection_policies]
            findings.append(f"Detection mode: {', '.join(names[:5])}")
        if prevention_policies:
            names = [p["name"] for p in prevention_policies]
            findings.append(f"Prevention mode (also provides detection): {', '.join(names[:5])}")

        return {
            "isIDSEnabled": True,
            "intrusionPoliciesFound": len(policies),
            "intrusionPolicyNames": all_policy_names[:10],
            "detectionModePolicies": len(detection_policies),
            "preventionModePolicies": len(prevention_policies),
            "findings": findings
        }
    except Exception as e:
        return {"isIDSEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isIDSEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            names = eval_result.get("intrusionPolicyNames", [])
            if names:
                pass_reasons.append(f"Intrusion policies: {', '.join(names[:5])}")
            det = eval_result.get("detectionModePolicies", 0)
            prev = eval_result.get("preventionModePolicies", 0)
            pass_reasons.append(f"{det} detection-mode, {prev} prevention-mode policy/policies")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create intrusion policies in FMC under Policies > Intrusion")
            recommendations.append("Apply intrusion policies to access control rules to enable network threat detection")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "intrusionPoliciesFound": extra_fields.get("intrusionPoliciesFound", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
