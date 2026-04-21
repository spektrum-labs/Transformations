"""\nTransformation: isFirewallEnabled\nVendor: Cato Networks  |  Category: Firewall\nEvaluates: Checks if the Internet Firewall or WAN Firewall policy is enabled in Cato Networks\nby evaluating the enabled field on the internetFirewall.policy and wanFirewall.policy objects\nreturned by the getFirewallPolicy query.\n"""
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
    Core evaluation logic for isFirewallEnabled.

    The getFirewallPolicy returnSpec maps data.policy -> policy, so the merged
    asset data exposes a top-level 'policy' key containing:
      policy.internetFirewall.policy.enabled  (bool)
      policy.wanFirewall.policy.enabled       (bool)

    The criteria passes when at least one of the two firewall policies is enabled.
    """
    try:
        policy_root = data.get("policy", {})
        if not isinstance(policy_root, dict):
            policy_root = {}

        # Internet Firewall
        internet_fw = policy_root.get("internetFirewall", {})
        if not isinstance(internet_fw, dict):
            internet_fw = {}
        internet_policy = internet_fw.get("policy", {})
        if not isinstance(internet_policy, dict):
            internet_policy = {}
        internet_enabled = internet_policy.get("enabled", False)
        internet_rules = internet_policy.get("rules", [])
        if not isinstance(internet_rules, list):
            internet_rules = []
        internet_rule_count = len(internet_rules)

        # WAN Firewall
        wan_fw = policy_root.get("wanFirewall", {})
        if not isinstance(wan_fw, dict):
            wan_fw = {}
        wan_policy = wan_fw.get("policy", {})
        if not isinstance(wan_policy, dict):
            wan_policy = {}
        wan_enabled = wan_policy.get("enabled", False)
        wan_rules = wan_policy.get("rules", [])
        if not isinstance(wan_rules, list):
            wan_rules = []
        wan_rule_count = len(wan_rules)

        is_enabled = True if (internet_enabled or wan_enabled) else False

        return {
            "isFirewallEnabled": is_enabled,
            "internetFirewallEnabled": True if internet_enabled else False,
            "wanFirewallEnabled": True if wan_enabled else False,
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
            pass_reasons.append("At least one Cato Networks firewall policy is enabled")
            if internet_enabled:
                pass_reasons.append("Internet Firewall policy is enabled")
            if wan_enabled:
                pass_reasons.append("WAN Firewall policy is enabled")
        else:
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            else:
                fail_reasons.append("Neither Internet Firewall nor WAN Firewall policy is enabled")
            recommendations.append(
                "Enable the Internet Firewall and/or WAN Firewall policy in the Cato Management "
                "Application under Security > Internet Firewall or Security > WAN Firewall"
            )

        if not internet_enabled:
            additional_findings.append({
                "metric": "internetFirewallEnabled",
                "status": "fail",
                "reason": "Internet Firewall policy is not enabled",
                "recommendation": "Enable the Internet Firewall policy in Cato CMA"
            })
        else:
            additional_findings.append({
                "metric": "internetFirewallEnabled",
                "status": "pass",
                "reason": "Internet Firewall policy is enabled with " + str(internet_rule_count) + " rule(s)"
            })

        if not wan_enabled:
            additional_findings.append({
                "metric": "wanFirewallEnabled",
                "status": "fail",
                "reason": "WAN Firewall policy is not enabled",
                "recommendation": "Enable the WAN Firewall policy in Cato CMA"
            })
        else:
            additional_findings.append({
                "metric": "wanFirewallEnabled",
                "status": "pass",
                "reason": "WAN Firewall policy is enabled with " + str(wan_rule_count) + " rule(s)"
            })

        return create_response(
            result={
                criteriaKey: result_value,
                "internetFirewallEnabled": internet_enabled,
                "wanFirewallEnabled": wan_enabled,
                "internetFirewallRuleCount": internet_rule_count,
                "wanFirewallRuleCount": wan_rule_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "internetFirewallEnabled": internet_enabled,
                "wanFirewallEnabled": wan_enabled,
                "internetFirewallRuleCount": internet_rule_count,
                "wanFirewallRuleCount": wan_rule_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
