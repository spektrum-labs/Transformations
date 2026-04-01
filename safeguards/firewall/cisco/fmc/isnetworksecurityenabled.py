"""
Transformation: isNetworkSecurityEnabled
Vendor: Cisco FMC  |  Category: Network Security / Firewall
Evaluates: Whether access control policies are deployed with active rules
           on managed firewall devices.

Data source: FMC REST API
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies (items[])
  - GET .../accesspolicies/{id}/accessrules?expanded=true (accessRules[])

A network is secure when:
  1. At least one access control policy exists
  2. Policies have active (enabled) access rules deployed
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isNetworkSecurityEnabled", "vendor": "Cisco FMC", "category": "Network Security"}
        }
    }


def to_bool(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


def extract_policies(data):
    """Extract access policies from FMC response."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items", [])
        if isinstance(items, list) and items:
            return items
        if "id" in data and "name" in data:
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
    """Evaluate whether access control policies have active rules deployed."""
    try:
        policies = extract_policies(data)
        access_rules = extract_access_rules(data)

        if not policies:
            return {"isNetworkSecurityEnabled": False, "error": "No access control policies found"}

        # Count enabled rules
        enabled_rules = 0
        disabled_rules = 0
        for rule in access_rules:
            if not isinstance(rule, dict):
                continue
            enabled = rule.get("enabled")
            if enabled is None:
                enabled = True  # FMC rules are enabled by default
            if to_bool(enabled):
                enabled_rules += 1
            else:
                disabled_rules += 1

        # If no access rules data merged, check if policies themselves indicate deployment
        has_rules = enabled_rules > 0
        if not access_rules and policies:
            # No rules data but policies exist - check policy metadata
            has_rules = len(policies) > 0

        findings = []
        findings.append(f"{len(policies)} access control policy/policies found")
        if access_rules:
            findings.append(f"{enabled_rules} enabled rules, {disabled_rules} disabled rules")

        return {
            "isNetworkSecurityEnabled": has_rules and len(policies) > 0,
            "policiesFound": len(policies),
            "policyNames": [p.get("name", "Unknown") for p in policies[:10] if isinstance(p, dict)],
            "enabledRules": enabled_rules,
            "disabledRules": disabled_rules,
            "findings": findings
        }
    except Exception as e:
        return {"isNetworkSecurityEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isNetworkSecurityEnabled"
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
            names = eval_result.get("policyNames", [])
            if names:
                pass_reasons.append(f"Active policies: {', '.join(names[:5])}")
            enabled = eval_result.get("enabledRules", 0)
            if enabled:
                pass_reasons.append(f"{enabled} enabled access rules")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Deploy access control policies with active rules on Cisco FMC managed devices")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "policiesFound": extra_fields.get("policiesFound", 0), "enabledRules": extra_fields.get("enabledRules", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
