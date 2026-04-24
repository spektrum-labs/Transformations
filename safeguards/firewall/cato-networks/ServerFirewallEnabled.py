"""
Transformation: ServerFirewallEnabled
Vendor: Cato Networks  |  Category: Firewall
Evaluates: Whether the WAN Firewall policy is enabled in Cato Networks.
The WAN Firewall controls access to WAN resources and server-to-server traffic.
Returns true if wanFirewall.policy.enabled is true.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "ServerFirewallEnabled", "vendor": "Cato Networks", "category": "Firewall"}
        }
    }


def count_active_rules(rules):
    """Count rules where enabled is true."""
    if not rules:
        return 0
    count = 0
    for item in rules:
        rule = item.get("rule", {})
        if rule.get("enabled", False):
            count = count + 1
    return count


def evaluate(data):
    """Core evaluation logic for ServerFirewallEnabled."""
    try:
        # The returnSpec for getWanFirewallPolicy resolves to data.policy.wanFirewall.policy
        # Shape: { "enabled": bool, "rules": [ { "rule": { ... } } ] }
        # Handle case where data is the full policy wrapper containing wanFirewall key
        policy = data
        if "wanFirewall" in data:
            wan_fw = data.get("wanFirewall", {})
            policy = wan_fw.get("policy", {})

        wan_enabled = policy.get("enabled", False)
        rules_raw = policy.get("rules", [])
        active_rule_count = count_active_rules(rules_raw)
        total_rule_count = len(rules_raw) if rules_raw else 0

        return {
            "ServerFirewallEnabled": wan_enabled,
            "wanFirewallEnabled": wan_enabled,
            "totalRules": total_rule_count,
            "activeRules": active_rule_count
        }
    except Exception as e:
        return {"ServerFirewallEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "ServerFirewallEnabled"
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
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        active_rules = eval_result.get("activeRules", 0)
        total_rules = eval_result.get("totalRules", 0)

        if result_value:
            pass_reasons.append("WAN Firewall policy is enabled in Cato Networks")
            pass_reasons.append("Active rules: " + str(active_rules) + " of " + str(total_rules) + " total")
        else:
            if "error" in eval_result:
                fail_reasons.append("Transformation error: " + eval_result["error"])
            else:
                fail_reasons.append("WAN Firewall policy is not enabled in Cato Networks")
            recommendations.append("Enable the WAN Firewall policy in Cato Networks to protect server-to-server and WAN resource traffic")
            recommendations.append("Navigate to Security > WAN Firewall in the Cato Management Application and set the policy to enabled")

        additional_findings.append("Total WAN Firewall rules defined: " + str(total_rules))
        additional_findings.append("Active WAN Firewall rules: " + str(active_rules))

        return create_response(
            result={
                criteriaKey: result_value,
                "wanFirewallEnabled": eval_result.get("wanFirewallEnabled", False),
                "totalRules": total_rules,
                "activeRules": active_rules
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"wanFirewallEnabled": result_value, "totalRules": total_rules},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
