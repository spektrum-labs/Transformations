"""
Transformation: isFirewallLoggingEnabled
Vendor: Cato Networks  |  Category: Firewall
Evaluates: Whether firewall event tracking/logging is enabled on at least one active rule
in either the Internet Firewall policy or the WAN Firewall policy.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallLoggingEnabled", "vendor": "Cato Networks", "category": "Firewall"}
        }
    }


def check_policy_logging(policy_data):
    """Return (policy_enabled, logging_enabled, logged_rule_count, total_active_rules)."""
    policy_enabled = policy_data.get("enabled", False)
    rules = policy_data.get("rules", [])
    logging_enabled = False
    logged_rule_count = 0
    total_active_rules = 0
    for rule_wrapper in rules:
        rule = rule_wrapper.get("rule", rule_wrapper)
        if rule.get("enabled", False):
            total_active_rules = total_active_rules + 1
            tracking = rule.get("tracking", {})
            event = tracking.get("event", {})
            if event.get("enabled", False):
                logging_enabled = True
                logged_rule_count = logged_rule_count + 1
    return policy_enabled, logging_enabled, logged_rule_count, total_active_rules


def evaluate(data):
    """
    Checks both the Internet Firewall policy and the WAN Firewall policy for event
    tracking/logging on active rules. The merged input may contain:
      - "internetFirewall": {"policy": {..., "rules": [...]}}
      - "wanFirewall":      {"policy": {..., "rules": [...]}}
    or (shallow-merge fallback) just "policy" at the top level.
    """
    try:
        internet_fw = data.get("internetFirewall", {})
        wan_fw = data.get("wanFirewall", {})

        # Shallow-merge fallback: if neither specific key exists, treat top-level as a policy block
        if not internet_fw and not wan_fw:
            fallback_policy = data.get("policy", {})
            internet_fw = {"policy": fallback_policy}

        internet_policy_data = internet_fw.get("policy", {})
        wan_policy_data = wan_fw.get("policy", {})

        inet_policy_enabled, inet_logging, inet_logged, inet_active = check_policy_logging(internet_policy_data)
        wan_policy_enabled, wan_logging, wan_logged, wan_active = check_policy_logging(wan_policy_data)

        logging_enabled = inet_logging or wan_logging

        return {
            "isFirewallLoggingEnabled": logging_enabled,
            "internetFirewallPolicyEnabled": inet_policy_enabled,
            "internetFirewallLoggingEnabled": inet_logging,
            "internetFirewallLoggedRuleCount": inet_logged,
            "internetFirewallActiveRuleCount": inet_active,
            "wanFirewallPolicyEnabled": wan_policy_enabled,
            "wanFirewallLoggingEnabled": wan_logging,
            "wanFirewallLoggedRuleCount": wan_logged,
            "wanFirewallActiveRuleCount": wan_active,
        }
    except Exception as e:
        return {"isFirewallLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isFirewallLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Firewall event logging is enabled on at least one active rule.")
            if eval_result.get("internetFirewallLoggingEnabled", False):
                pass_reasons.append(
                    "Internet Firewall: " + str(eval_result.get("internetFirewallLoggedRuleCount", 0)) +
                    " of " + str(eval_result.get("internetFirewallActiveRuleCount", 0)) +
                    " active rules have event logging enabled."
                )
            if eval_result.get("wanFirewallLoggingEnabled", False):
                pass_reasons.append(
                    "WAN Firewall: " + str(eval_result.get("wanFirewallLoggedRuleCount", 0)) +
                    " of " + str(eval_result.get("wanFirewallActiveRuleCount", 0)) +
                    " active rules have event logging enabled."
                )
        else:
            fail_reasons.append("No active firewall rule has event tracking/logging enabled.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Enable event tracking on Internet Firewall and WAN Firewall rules "
                "under Security > Internet Firewall / WAN Firewall > Rule > Tracking."
            )

        if not eval_result.get("internetFirewallPolicyEnabled", False):
            additional_findings.append("Internet Firewall policy is disabled or not detected.")
        if not eval_result.get("wanFirewallPolicyEnabled", False):
            additional_findings.append("WAN Firewall policy is disabled or not detected.")

        input_summary = {
            "internetFirewallActiveRuleCount": eval_result.get("internetFirewallActiveRuleCount", 0),
            "wanFirewallActiveRuleCount": eval_result.get("wanFirewallActiveRuleCount", 0),
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
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
