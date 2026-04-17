"""
Transformation: isFirewallEnabled
Vendor: Cato Networks  |  Category: Firewall
Evaluates: Inspects the internetFirewall.policy.enabled and wanFirewall.policy.enabled
fields in the policy response to determine if the firewall is enabled for the Cato account.
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isFirewallEnabled",
                "vendor": "Cato Networks",
                "category": "Firewall"
            }
        }
    }


def evaluate(data):
    """
    Checks both internetFirewall.policy.enabled and wanFirewall.policy.enabled.
    Returns isFirewallEnabled=True only when both policies report enabled=True.
    Individual states are also surfaced for traceability.
    """
    try:
        internet_fw = data.get("internetFirewall", {})
        wan_fw = data.get("wanFirewall", {})

        internet_policy = internet_fw.get("policy", {})
        wan_policy = wan_fw.get("policy", {})

        internet_enabled = internet_policy.get("enabled", False)
        wan_enabled = wan_policy.get("enabled", False)

        internet_rules = internet_policy.get("rules", [])
        wan_rules = wan_policy.get("rules", [])

        if not isinstance(internet_rules, list):
            internet_rules = []
        if not isinstance(wan_rules, list):
            wan_rules = []

        internet_rule_count = len(internet_rules)
        wan_rule_count = len(wan_rules)

        is_enabled = internet_enabled and wan_enabled

        return {
            "isFirewallEnabled": is_enabled,
            "internetFirewallEnabled": internet_enabled,
            "wanFirewallEnabled": wan_enabled,
            "internetFirewallRuleCount": internet_rule_count,
            "wanFirewallRuleCount": wan_rule_count
        }
    except Exception as e:
        return {"isFirewallEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isFirewallEnabled"
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

        internet_enabled = eval_result.get("internetFirewallEnabled", False)
        wan_enabled = eval_result.get("wanFirewallEnabled", False)
        internet_rule_count = eval_result.get("internetFirewallRuleCount", 0)
        wan_rule_count = eval_result.get("wanFirewallRuleCount", 0)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Both Internet Firewall and WAN Firewall policies are enabled.")
            pass_reasons.append("internetFirewall.policy.enabled: " + str(internet_enabled))
            pass_reasons.append("wanFirewall.policy.enabled: " + str(wan_enabled))
        else:
            if not internet_enabled:
                fail_reasons.append("Internet Firewall policy is not enabled (internetFirewall.policy.enabled = False).")
                recommendations.append(
                    "Enable the Internet Firewall policy in the Cato Management Application "
                    "under Security > Internet Firewall."
                )
            if not wan_enabled:
                fail_reasons.append("WAN Firewall policy is not enabled (wanFirewall.policy.enabled = False).")
                recommendations.append(
                    "Enable the WAN Firewall policy in the Cato Management Application "
                    "under Security > WAN Firewall."
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        additional_findings.append(
            "Internet Firewall active rule count: " + str(internet_rule_count)
        )
        additional_findings.append(
            "WAN Firewall active rule count: " + str(wan_rule_count)
        )

        result = {
            criteriaKey: result_value,
            "internetFirewallEnabled": internet_enabled,
            "wanFirewallEnabled": wan_enabled,
            "internetFirewallRuleCount": internet_rule_count,
            "wanFirewallRuleCount": wan_rule_count
        }

        input_summary = {
            "internetFirewallEnabled": internet_enabled,
            "wanFirewallEnabled": wan_enabled,
            "internetFirewallRuleCount": internet_rule_count,
            "wanFirewallRuleCount": wan_rule_count
        }

        return create_response(
            result=result,
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
