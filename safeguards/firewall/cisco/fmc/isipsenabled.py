"""
Transformation: isIPSEnabled
Vendor: Cisco FMC  |  Category: Firewall
Evaluates: Whether Intrusion Prevention System (IPS) is active on the firewall.

Data source: FMC REST API
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/intrusionpolicies (list)
  - GET .../intrusionpolicies/{id} (detail, iterated per policy)

The list endpoint returns summary objects (id, name, type) without
inspectionMode. The detail endpoint returns the full policy including
inspectionMode (DETECTION or PREVENTION).

IPS is enabled when:
  1. At least one intrusion policy exists in FMC
  2. At least one policy detail has inspectionMode == PREVENTION

Workflow merges detail responses into the "policyDetails" key.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isIPSEnabled", "vendor": "Cisco FMC", "category": "Firewall"}
        }
    }


def extract_policy_details(data):
    """Extract intrusion policy details from the merged policyDetails key.

    The workflow iterates over intrusion policies and merges each detail
    response into data["policyDetails"]. Each entry is the full policy
    object from GET /intrusionpolicies/{id}.
    """
    if not isinstance(data, dict):
        return []
    raw = data.get("policyDetails", [])
    if isinstance(raw, list):
        details = []
        for entry in raw:
            if isinstance(entry, dict):
                # Could be a direct policy object or wrapped in items
                if "items" in entry and isinstance(entry["items"], list):
                    details.extend(entry["items"])
                elif "id" in entry:
                    details.append(entry)
            elif isinstance(entry, list):
                details.extend([e for e in entry if isinstance(e, dict)])
        return details
    if isinstance(raw, dict) and "id" in raw:
        return [raw]
    return []


def extract_intrusion_policies_summary(data):
    """Extract summary intrusion policies from the list endpoint response."""
    if not isinstance(data, dict):
        return []
    items = data.get("items", [])
    if isinstance(items, list):
        return [p for p in items if isinstance(p, dict)]
    return []


def evaluate(data):
    """Evaluate whether IPS (prevention mode) is active."""
    try:
        summary_policies = extract_intrusion_policies_summary(data)
        detail_policies = extract_policy_details(data)

        if not summary_policies and not detail_policies:
            return {"isIPSEnabled": False, "error": "No intrusion policies found in FMC"}

        # Use details if available (they have inspectionMode), fall back to summary
        policies_to_check = detail_policies if detail_policies else summary_policies

        prevention_policies = []
        detection_only_policies = []
        unknown_mode_policies = []

        for policy in policies_to_check:
            name = policy.get("name", "Unknown")
            mode = (policy.get("inspectionMode", "") or "").upper()

            if mode == "PREVENTION":
                prevention_policies.append(name)
            elif mode == "DETECTION":
                detection_only_policies.append(name)
            else:
                unknown_mode_policies.append(name)

        ips_enabled = len(prevention_policies) > 0

        findings = []
        total = len(summary_policies) or len(policies_to_check)
        findings.append(f"{total} intrusion policy/policies configured in FMC")
        findings.append(f"{len(detail_policies)} policy details retrieved with inspectionMode")
        if prevention_policies:
            findings.append(f"Prevention mode (IPS active): {', '.join(prevention_policies[:5])}")
        if detection_only_policies:
            findings.append(f"Detection-only mode (IDS only): {', '.join(detection_only_policies[:5])}")
        if unknown_mode_policies:
            findings.append(f"Unknown mode (detail not retrieved): {', '.join(unknown_mode_policies[:5])}")

        return {
            "isIPSEnabled": ips_enabled,
            "intrusionPoliciesFound": total,
            "policyDetailsRetrieved": len(detail_policies),
            "preventionPolicies": len(prevention_policies),
            "preventionPolicyNames": prevention_policies[:10],
            "detectionOnlyPolicies": len(detection_only_policies),
            "detectionOnlyPolicyNames": detection_only_policies[:10],
            "findings": findings
        }
    except Exception as e:
        return {"isIPSEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isIPSEnabled"
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
            names = eval_result.get("preventionPolicyNames", [])
            if names:
                pass_reasons.append(f"Prevention-mode policies: {', '.join(names[:5])}")
            prev = eval_result.get("preventionPolicies", 0)
            det = eval_result.get("detectionOnlyPolicies", 0)
            pass_reasons.append(f"{prev} prevention-mode, {det} detection-only policy/policies")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            det = eval_result.get("detectionOnlyPolicies", 0)
            if det > 0:
                det_names = eval_result.get("detectionOnlyPolicyNames", [])
                fail_reasons.append(f"{det} intrusion policy/policies found but all in detection-only mode: {', '.join(det_names[:5])}")
            recommendations.append("Set intrusion policy inspectionMode to PREVENTION in FMC under Policies > Intrusion > Edit Policy")
            recommendations.append("PREVENTION mode actively blocks threats in addition to detecting them")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "preventionPolicies": extra_fields.get("preventionPolicies", 0), "intrusionPoliciesFound": extra_fields.get("intrusionPoliciesFound", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
