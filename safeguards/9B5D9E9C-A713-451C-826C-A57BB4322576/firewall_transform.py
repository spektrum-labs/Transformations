"""
Transformation: firewall_transform
Vendor: Firewall (Cato Networks)
Category: Network Security / Firewall

Evaluates if Firewalls are set up properly including internet firewall and WAN network rules.
"""

import json
import ast
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "firewall_transform",
                "vendor": "Firewall",
                "category": "Network Security"
            }
        }
    }


def transform(input):
    is_firewall_enabled = False
    is_firewall_logging_enabled = False
    is_internet_firewall_enabled = False
    is_wan_network_enabled = False
    internet_firewall_rules = []
    wan_network_rules = []

    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        input = _parse_input(input)
        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isFirewallEnabled": False, "isFirewallLoggingEnabled": False, "isFirewallConfigured": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if isinstance(data, dict):
            if 'response' in data:
                data = _parse_input(data['response'])
            if 'result' in data:
                data = _parse_input(data['result'])

            firewall_data = _parse_input(data['firewall']) if 'firewall' in data else data
            wan_network_data = _parse_input(data['wanNetwork']) if 'wanNetwork' in data else data

            is_firewall_enabled = True if data.get('isFirewallEnabled', False) else False

            if 'data' in firewall_data:
                firewall_data = _parse_input(firewall_data['data'])
                if 'policy' in firewall_data:
                    firewall_data = _parse_input(firewall_data['policy'])
                    if 'internetFirewall' in firewall_data:
                        firewall_policy = _parse_input(firewall_data['internetFirewall'])
                        if 'policy' in firewall_policy:
                            firewall_policy = _parse_input(firewall_policy['policy'])
                            if 'enabled' in firewall_policy:
                                is_internet_firewall_enabled = True if firewall_policy.get('enabled', False) else False
                            if 'rules' in firewall_policy:
                                internet_firewall_rules_raw = firewall_policy['rules']
                                for rule in internet_firewall_rules_raw:
                                    if 'rule' in rule and 'name' in rule['rule']:
                                        internet_firewall_rules.append(rule['rule']['name'])

            if 'data' in wan_network_data:
                wan_network_data = _parse_input(wan_network_data['data'])
                if 'policy' in wan_network_data:
                    wan_network_data = _parse_input(wan_network_data['policy'])
                    if 'wanNetwork' in wan_network_data:
                        wan_network_policy = _parse_input(wan_network_data['wanNetwork'])
                        if 'policy' in wan_network_policy:
                            wan_network_policy = _parse_input(wan_network_policy['policy'])
                            if 'enabled' in wan_network_policy:
                                is_wan_network_enabled = True if wan_network_policy.get('enabled', False) else False
                            if 'rules' in wan_network_policy:
                                wan_network_rules_raw = wan_network_policy['rules']
                                for rule in wan_network_rules_raw:
                                    if 'rule' in rule and 'name' in rule['rule']:
                                        wan_network_rules.append(rule['rule']['name'])

            is_firewall_logging_enabled = True if data.get('isFirewallLoggingEnabled', False) else False

            if 'data' in data:
                audit_data = _parse_input(data['data'])
                if 'auditFeed' in audit_data:
                    audit_logs_raw = _parse_input(audit_data['auditFeed'])
                    if 'fetchedCount' in audit_logs_raw:
                        is_firewall_logging_enabled = True if audit_logs_raw.get('fetchedCount', 0) > 0 else False

        is_firewall_enabled_final = is_firewall_enabled or (is_internet_firewall_enabled and is_wan_network_enabled)
        is_firewall_configured = len(internet_firewall_rules) > 0 or len(wan_network_rules) > 0

        if is_firewall_enabled_final:
            pass_reasons.append("Firewall is enabled")
        else:
            fail_reasons.append("Firewall is not enabled")
            recommendations.append("Enable firewall for network security")

        if is_firewall_logging_enabled:
            pass_reasons.append("Firewall logging is enabled")
        else:
            fail_reasons.append("Firewall logging is not enabled")
            recommendations.append("Enable firewall logging for audit and compliance")

        if is_firewall_configured:
            pass_reasons.append(f"Firewall is configured with {len(internet_firewall_rules)} internet rules and {len(wan_network_rules)} WAN rules")
        else:
            fail_reasons.append("Firewall rules are not configured")
            recommendations.append("Configure firewall rules for proper network security")

        return create_response(
            result={
                "isFirewallEnabled": is_firewall_enabled_final,
                "isFirewallLoggingEnabled": is_firewall_logging_enabled,
                "isFirewallConfigured": is_firewall_configured,
                "internetFirewallRules": internet_firewall_rules,
                "wanNetworkRules": wan_network_rules
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "firewallEnabled": is_firewall_enabled_final,
                "loggingEnabled": is_firewall_logging_enabled,
                "internetFirewallRulesCount": len(internet_firewall_rules),
                "wanNetworkRulesCount": len(wan_network_rules)
            }
        )

    except Exception as e:
        return create_response(
            result={
                "isFirewallEnabled": False,
                "isFirewallLoggingEnabled": is_firewall_logging_enabled,
                "isFirewallConfigured": is_firewall_enabled and is_firewall_logging_enabled
            },
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
