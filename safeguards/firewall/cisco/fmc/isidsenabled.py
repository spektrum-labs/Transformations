"""
Transformation: isIDSEnabled
Vendor: Cisco FMC  |  Category: Firewall
Evaluates: Whether Intrusion Detection System (IDS) is active on the firewall.

Data source: FMC REST API
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/intrusionpolicies
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies (items[])
  - GET .../accesspolicies/{id}/accessrules?expanded=true (accessRules[])

IDS is enabled when:
  1. At least one intrusion policy exists in FMC
  2. At least one enabled access rule has an intrusion policy (ipsPolicy) assigned
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
    # Direct items from the intrusion policies endpoint
    items = data.get("items", [])
    if isinstance(items, list) and items:
        return [p for p in items if isinstance(p, dict)]
    # Single policy object
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
    """Evaluate whether IDS is active via intrusion policies assigned to access rules."""
    try:
        intrusion_policies = extract_intrusion_policies(data)
        access_rules = extract_access_rules(data)

        if not intrusion_policies:
            return {"isIDSEnabled": False, "error": "No intrusion policies found in FMC"}

        policy_names = [p.get("name", "Unknown") for p in intrusion_policies]

        if not access_rules:
            return {
                "isIDSEnabled": False,
                "error": "No access rules found to evaluate intrusion policy assignments",
                "intrusionPoliciesFound": len(intrusion_policies),
                "intrusionPolicyNames": policy_names[:10]
            }

        # Check enabled access rules for ipsPolicy assignment
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
                "isIDSEnabled": False,
                "error": "No enabled access rules found",
                "intrusionPoliciesFound": len(intrusion_policies)
            }

        rules_with_ids = []
        rules_without_ids = []

        for rule in enabled_rules:
            rule_name = rule.get("name", "Unknown")
            ips_policy = rule.get("ipsPolicy")
            if isinstance(ips_policy, dict) and ips_policy.get("id"):
                rules_with_ids.append({
                    "ruleName": rule_name,
                    "intrusionPolicy": ips_policy.get("name", "Unknown")
                })
            else:
                rules_without_ids.append(rule_name)

        ids_enabled = len(rules_with_ids) > 0

        findings = []
        findings.append(f"{len(intrusion_policies)} intrusion policy/policies configured: {', '.join(policy_names[:5])}")
        findings.append(f"{len(rules_with_ids)} of {len(enabled_rules)} enabled access rules have intrusion inspection assigned")
        if rules_without_ids:
            findings.append(f"Rules without intrusion inspection: {', '.join(rules_without_ids[:10])}")

        return {
            "isIDSEnabled": ids_enabled,
            "intrusionPoliciesFound": len(intrusion_policies),
            "intrusionPolicyNames": policy_names[:10],
            "totalEnabledRules": len(enabled_rules),
            "rulesWithIDS": len(rules_with_ids),
            "rulesWithoutIDS": len(rules_without_ids),
            "rulesWithoutIDSNames": rules_without_ids[:20],
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
            policies = eval_result.get("intrusionPolicyNames", [])
            if policies:
                pass_reasons.append(f"Intrusion policies: {', '.join(policies[:5])}")
            rules_with = eval_result.get("rulesWithIDS", 0)
            total = eval_result.get("totalEnabledRules", 0)
            pass_reasons.append(f"{rules_with}/{total} enabled rules have intrusion detection assigned")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure intrusion policies in FMC and assign them to access control rules via the ipsPolicy setting")
            recommendations.append("Ensure at least one intrusion policy is applied to enabled access rules for network threat detection")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "intrusionPoliciesFound": extra_fields.get("intrusionPoliciesFound", 0), "rulesWithIDS": extra_fields.get("rulesWithIDS", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
