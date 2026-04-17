"""
Transformation: isFirewallEnabled
Vendor: Cato Networks  |  Category: Firewall
Evaluates: Whether the WAN Firewall or Internet Firewall (or both) is enabled
           for the account. Checks wanFirewall.policy.enabled and
           internetFirewall.policy.enabled from the Cato policy query.
           Returns true if at least one of the two firewall policies is enabled.
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
    Core evaluation logic for isFirewallEnabled.

    The returnSpec for getFirewallPolicy maps data.policy to the response root,
    so the data dict contains:
      data["wanFirewall"]["policy"]["enabled"]      -> bool
      data["internetFirewall"]["policy"]["enabled"] -> bool

    Pass condition: at least one of the two firewall policies is enabled.
    """
    try:
        wan_firewall = data.get("wanFirewall", {})
        internet_firewall = data.get("internetFirewall", {})

        wan_policy = wan_firewall.get("policy", {})
        internet_policy = internet_firewall.get("policy", {})

        wan_enabled = wan_policy.get("enabled", False)
        internet_enabled = internet_policy.get("enabled", False)

        # Coerce to bool in case the API returns string or None
        wan_enabled = wan_enabled is True
        internet_enabled = internet_enabled is True

        is_enabled = wan_enabled or internet_enabled

        return {
            "isFirewallEnabled": is_enabled,
            "wanFirewallEnabled": wan_enabled,
            "internetFirewallEnabled": internet_enabled
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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        wan_enabled = eval_result.get("wanFirewallEnabled", False)
        internet_enabled = eval_result.get("internetFirewallEnabled", False)

        if result_value:
            pass_reasons.append("At least one Cato Networks firewall policy is enabled.")
            if wan_enabled:
                pass_reasons.append("WAN Firewall policy is enabled.")
            if internet_enabled:
                pass_reasons.append("Internet Firewall policy is enabled.")
            if not wan_enabled:
                additional_findings.append("WAN Firewall policy is not enabled — consider enabling it for full coverage.")
            if not internet_enabled:
                additional_findings.append("Internet Firewall policy is not enabled — consider enabling it for full coverage.")
        else:
            fail_reasons.append("Neither the WAN Firewall nor the Internet Firewall policy is enabled.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enable the WAN Firewall and/or Internet Firewall policies in the Cato Management Application "
                "under Security > WAN Firewall / Internet Firewall."
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "wanFirewallEnabled": wan_enabled,
                "internetFirewallEnabled": internet_enabled
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
