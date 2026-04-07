"""
Transformation: isIPSEnabled
Vendor: Cisco FMC  |  Category: Firewall
Evaluates: Whether Intrusion Prevention System (IPS) is active on the firewall.

Data source: FMC REST API
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/intrusionpolicies
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies (items[])
  - GET .../accesspolicies/{id}/accessrules?expanded=true (accessRules[])

IPS is enabled when:
  1. At least one intrusion policy exists with inspectionMode set to PREVENTION
  2. At least one enabled access rule has a prevention-mode intrusion policy assigned

The key distinction from IDS: IDS only detects and alerts, while IPS actively
blocks malicious traffic. FMC intrusion policies use inspectionMode to control
this — DETECTION (IDS-only) vs PREVENTION (IPS, actively drops threats).
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


def to_bool(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


def extract_intrusion_policies(data):
    """Extract intrusion policies from the getIntrusionPolicies response."""
    if not isinstance(data, dict):
        return []
    items = data.get("items", [])
    if isinstance(items, list) and items:
        return [p for p in items if isinstance(p, dict)]
    if "id" in data and data.get("type", "") == "IntrusionPolicy":
        return [data]
    return []


def extract_access_rules(data):
    """Extract merged access rules from workflow output."""
    if not isinstance(data, dict):
        return []
    raw = data.get("accessRules", [])
    if isinstance(raw, list):
        rules = []
        for entry in raw:
            if isinstance(entry, dict) and "items" in entry:
                rules.extend(entry["items"] if isinstance(entry["items"], list) else [])
            elif isinstance(entry, dict):
                rules.append(entry)
            elif isinstance(entry, list):
                rules.extend(entry)
        return rules
    return []


def evaluate(data):
    """Evaluate whether IPS (prevention mode) is active via intrusion policies on access rules."""
    try:
        intrusion_policies = extract_intrusion_policies(data)
        access_rules = extract_access_rules(data)

        if not intrusion_policies:
            return {"isIPSEnabled": False, "error": "No intrusion policies found in FMC"}

        # Build lookup of intrusion policies by ID, categorize by mode
        policy_by_id = {}
        prevention_policies = []
        detection_only_policies = []

        for policy in intrusion_policies:
            pid = policy.get("id", "")
            pname = policy.get("name", "Unknown")
            mode = policy.get("inspectionMode", "").upper()
            policy_by_id[pid] = policy

            if mode == "PREVENTION":
                prevention_policies.append(pname)
            else:
                detection_only_policies.append(pname)

        if not prevention_policies:
            findings = []
            findings.append(f"{len(intrusion_policies)} intrusion policy/policies found but none in PREVENTION mode")
            if detection_only_policies:
                findings.append(f"Detection-only policies: {', '.join(detection_only_policies[:5])}")
            return {
                "isIPSEnabled": False,
                "error": "No intrusion policies configured in PREVENTION mode",
                "intrusionPoliciesFound": len(intrusion_policies),
                "preventionPolicies": 0,
                "detectionOnlyPolicies": len(detection_only_policies),
                "detectionOnlyPolicyNames": detection_only_policies[:10],
                "findings": findings
            }

        if not access_rules:
            return {
                "isIPSEnabled": False,
                "error": "No access rules found to evaluate intrusion policy assignments",
                "intrusionPoliciesFound": len(intrusion_policies),
                "preventionPolicies": len(prevention_policies),
                "preventionPolicyNames": prevention_policies[:10]
            }

        # Check enabled access rules for ipsPolicy in prevention mode
        enabled_rules = []
        for rule in access_rules:
            if not isinstance(rule, dict):
                continue
            enabled = rule.get("enabled")
            if enabled is None:
                enabled = True
            if to_bool(enabled):
                enabled_rules.append(rule)

        if not enabled_rules:
            return {
                "isIPSEnabled": False,
                "error": "No enabled access rules found",
                "intrusionPoliciesFound": len(intrusion_policies),
                "preventionPolicies": len(prevention_policies)
            }

        rules_with_ips = []
        rules_with_ids_only = []
        rules_without_intrusion = []

        for rule in enabled_rules:
            rule_name = rule.get("name", "Unknown")
            ips_policy = rule.get("ipsPolicy")

            if not isinstance(ips_policy, dict) or not ips_policy.get("id"):
                rules_without_intrusion.append(rule_name)
                continue

            assigned_id = ips_policy.get("id", "")
            assigned_name = ips_policy.get("name", "Unknown")
            matched_policy = policy_by_id.get(assigned_id, {})
            mode = matched_policy.get("inspectionMode", "").upper()

            if mode == "PREVENTION":
                rules_with_ips.append({
                    "ruleName": rule_name,
                    "intrusionPolicy": assigned_name,
                    "mode": "PREVENTION"
                })
            else:
                rules_with_ids_only.append({
                    "ruleName": rule_name,
                    "intrusionPolicy": assigned_name,
                    "mode": mode or "DETECTION"
                })

        ips_enabled = len(rules_with_ips) > 0

        findings = []
        findings.append(f"{len(prevention_policies)} intrusion policy/policies in PREVENTION mode: {', '.join(prevention_policies[:5])}")
        if detection_only_policies:
            findings.append(f"{len(detection_only_policies)} policy/policies in DETECTION-only mode: {', '.join(detection_only_policies[:5])}")
        findings.append(f"{len(rules_with_ips)} of {len(enabled_rules)} enabled rules have IPS (prevention) assigned")
        if rules_with_ids_only:
            ids_names = [r["ruleName"] for r in rules_with_ids_only]
            findings.append(f"Rules with detection-only intrusion policies: {', '.join(ids_names[:10])}")
        if rules_without_intrusion:
            findings.append(f"Rules without any intrusion inspection: {', '.join(rules_without_intrusion[:10])}")

        return {
            "isIPSEnabled": ips_enabled,
            "intrusionPoliciesFound": len(intrusion_policies),
            "preventionPolicies": len(prevention_policies),
            "preventionPolicyNames": prevention_policies[:10],
            "detectionOnlyPolicies": len(detection_only_policies),
            "totalEnabledRules": len(enabled_rules),
            "rulesWithIPS": len(rules_with_ips),
            "rulesWithIDSOnly": len(rules_with_ids_only),
            "rulesWithoutIntrusion": len(rules_without_intrusion),
            "rulesWithoutIntrusionNames": rules_without_intrusion[:20],
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
            policies = eval_result.get("preventionPolicyNames", [])
            if policies:
                pass_reasons.append(f"Prevention-mode policies: {', '.join(policies[:5])}")
            rules_with = eval_result.get("rulesWithIPS", 0)
            total = eval_result.get("totalEnabledRules", 0)
            pass_reasons.append(f"{rules_with}/{total} enabled rules have IPS (prevention) assigned")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            ids_only = eval_result.get("rulesWithIDSOnly", 0)
            if ids_only:
                fail_reasons.append(f"{ids_only} rule(s) have intrusion policies in detection-only mode")
            recommendations.append("Set intrusion policy inspectionMode to PREVENTION to actively block threats, not just detect them")
            recommendations.append("Assign prevention-mode intrusion policies to access control rules via the ipsPolicy setting")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "preventionPolicies": extra_fields.get("preventionPolicies", 0), "rulesWithIPS": extra_fields.get("rulesWithIPS", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
