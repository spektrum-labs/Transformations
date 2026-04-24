"""
Transformation: NetworkConfigurationSecure
Vendor: Cato Networks  |  Category: Firewall
Evaluates: Overall security configuration of both internetFirewall and wanFirewall policies.
Checks that both policies are enabled, that active rules are defined, and that event
tracking is configured on at least one rule in each policy.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "NetworkConfigurationSecure", "vendor": "Cato Networks", "category": "Firewall"}
        }
    }


def check_rules_have_tracking(rules):
    """Return True if at least one enabled rule has event tracking enabled."""
    if not rules:
        return False
    for item in rules:
        rule = item.get("rule", {})
        if not rule.get("enabled", False):
            continue
        tracking = rule.get("tracking", {})
        event = tracking.get("event", {})
        if event.get("enabled", False):
            return True
    return False


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
    """Core evaluation logic for NetworkConfigurationSecure."""
    try:
        fail_details = []

        # Extract internetFirewall policy
        inet_fw = data.get("internetFirewall", {})
        inet_policy = inet_fw.get("policy", {})
        inet_enabled = inet_policy.get("enabled", False)
        inet_rules_raw = inet_policy.get("rules", [])
        inet_active_count = count_active_rules(inet_rules_raw)
        inet_tracking = check_rules_have_tracking(inet_rules_raw)

        # Extract wanFirewall policy
        wan_fw = data.get("wanFirewall", {})
        wan_policy = wan_fw.get("policy", {})
        wan_enabled = wan_policy.get("enabled", False)
        wan_rules_raw = wan_policy.get("rules", [])
        wan_active_count = count_active_rules(wan_rules_raw)
        wan_tracking = check_rules_have_tracking(wan_rules_raw)

        # Evaluate conditions
        if not inet_enabled:
            fail_details.append("Internet Firewall policy is not enabled")
        if not wan_enabled:
            fail_details.append("WAN Firewall policy is not enabled")
        if inet_active_count == 0:
            fail_details.append("No active rules found in Internet Firewall policy")
        if wan_active_count == 0:
            fail_details.append("No active rules found in WAN Firewall policy")
        if not inet_tracking and not wan_tracking:
            fail_details.append("Event tracking is not enabled on any active rule in either policy")

        is_secure = (
            inet_enabled and
            wan_enabled and
            inet_active_count > 0 and
            wan_active_count > 0 and
            (inet_tracking or wan_tracking)
        )

        return {
            "NetworkConfigurationSecure": is_secure,
            "internetFirewallEnabled": inet_enabled,
            "wanFirewallEnabled": wan_enabled,
            "internetFirewallActiveRules": inet_active_count,
            "wanFirewallActiveRules": wan_active_count,
            "internetFirewallEventTrackingEnabled": inet_tracking,
            "wanFirewallEventTrackingEnabled": wan_tracking,
            "failDetails": fail_details
        }
    except Exception as e:
        return {"NetworkConfigurationSecure": False, "error": str(e)}


def transform(input):
    criteriaKey = "NetworkConfigurationSecure"
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
        fail_details = eval_result.get("failDetails", [])
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Both Internet Firewall and WAN Firewall policies are enabled")
            pass_reasons.append("Active rules are defined in both policies")
            pass_reasons.append("Event tracking is configured on at least one active rule")
        else:
            if "error" in eval_result:
                fail_reasons.append("Transformation error: " + eval_result["error"])
            else:
                for detail in fail_details:
                    fail_reasons.append(detail)
            recommendations.append("Enable both Internet Firewall and WAN Firewall policies in Cato Networks")
            recommendations.append("Define active ALLOW and BLOCK rules for both firewall policies")
            recommendations.append("Enable event tracking on at least one active rule to ensure audit visibility")

        additional_findings.append("Internet Firewall enabled: " + str(eval_result.get("internetFirewallEnabled", False)))
        additional_findings.append("WAN Firewall enabled: " + str(eval_result.get("wanFirewallEnabled", False)))
        additional_findings.append("Internet Firewall active rules: " + str(eval_result.get("internetFirewallActiveRules", 0)))
        additional_findings.append("WAN Firewall active rules: " + str(eval_result.get("wanFirewallActiveRules", 0)))
        additional_findings.append("Internet Firewall event tracking: " + str(eval_result.get("internetFirewallEventTrackingEnabled", False)))
        additional_findings.append("WAN Firewall event tracking: " + str(eval_result.get("wanFirewallEventTrackingEnabled", False)))

        input_summary = {
            "internetFirewallEnabled": eval_result.get("internetFirewallEnabled", False),
            "wanFirewallEnabled": eval_result.get("wanFirewallEnabled", False),
            "internetFirewallActiveRules": eval_result.get("internetFirewallActiveRules", 0),
            "wanFirewallActiveRules": eval_result.get("wanFirewallActiveRules", 0)
        }

        return create_response(
            result={
                criteriaKey: result_value,
                "internetFirewallEnabled": eval_result.get("internetFirewallEnabled", False),
                "wanFirewallEnabled": eval_result.get("wanFirewallEnabled", False),
                "internetFirewallActiveRules": eval_result.get("internetFirewallActiveRules", 0),
                "wanFirewallActiveRules": eval_result.get("wanFirewallActiveRules", 0),
                "internetFirewallEventTrackingEnabled": eval_result.get("internetFirewallEventTrackingEnabled", False),
                "wanFirewallEventTrackingEnabled": eval_result.get("wanFirewallEventTrackingEnabled", False)
            },
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
