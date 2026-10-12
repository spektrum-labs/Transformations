"""
Transformation: firewall_transform
Vendor: Firewall (Cato Networks)
Category: Network Security / Firewall

Evaluates if Firewalls are set up properly including internet firewall and WAN network rules.

isFirewallLoggingEnabled is answered only from the audit feed. A feed that was read with fetchedCount above zero is True
and one read with fetchedCount 0 is the measured False. A feed that is absent, null, empty, not an object, or has no
readable fetchedCount (and a failed validation or an exception) was not measured: the answer is None with a
data-collection error, which is Not evaluated. A field of that name in the body is never read.
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
                "transformationId": "firewall_transform",
                "vendor": "Cato Networks",
                "category": "Firewall"
            }
        }
    }


AUDIT_FEED_NOT_READ = "Audit feed was missing or could not be read, so firewall logging was not evaluated"


def read_fetched_count(value):
    """A feed's fetchedCount as a whole number of entries, or None when it cannot be read as one.

    A bool, a negative number, a fraction, text that is not plain digits, null, a list or an object are unreadable.
    Plain digits as text ("7") read as the number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        try:
            whole = int(value)
        except (ValueError, OverflowError):
            return None
        return whole if whole == value and whole >= 0 else None
    if isinstance(value, str):
        text = value.strip()
        if text != "" and all(ch in "0123456789" for ch in text):
            return int(text)
    return None


def transform(input):
    is_firewall_enabled = False
    is_firewall_logging_enabled = None
    is_internet_firewall_enabled = False
    is_wan_network_enabled = False
    internet_firewall_rules = []
    wan_network_rules = []

    try:
        def parse_input(input):
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

        input = parse_input(input)
        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isFirewallEnabled": False, "isFirewallLoggingEnabled": None, "isFirewallConfigured": False},
                validation=validation,
                fail_reasons=["Input validation failed"],
                api_errors=[AUDIT_FEED_NOT_READ]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if isinstance(data, dict):
            if 'response' in data:
                data = parse_input(data['response'])
            if 'result' in data:
                data = parse_input(data['result'])

            firewall_data = parse_input(data['firewall']) if 'firewall' in data else data
            wan_network_data = parse_input(data['wanNetwork']) if 'wanNetwork' in data else data
            audit_data = parse_input(data['data']) if 'data' in data else data

            if 'data' in firewall_data:
                firewall_data = parse_input(firewall_data['data'])
                if 'policy' in firewall_data:
                    firewall_data = parse_input(firewall_data['policy'])
                    if 'internetFirewall' in firewall_data:
                        firewall_policy = parse_input(firewall_data['internetFirewall'])
                        if 'policy' in firewall_policy:
                            firewall_policy = parse_input(firewall_policy['policy'])
                            if 'enabled' in firewall_policy:
                                is_internet_firewall_enabled = True if firewall_policy.get('enabled', False) else False
                            if 'rules' in firewall_policy:
                                internet_firewall_rules_raw = firewall_policy['rules']
                                for rule in internet_firewall_rules_raw:
                                    if 'rule' in rule and 'name' in rule['rule']:
                                        internet_firewall_rules.append(rule['rule']['name'])

            if 'data' in wan_network_data:
                wan_network_data = parse_input(wan_network_data['data'])
                if 'policy' in wan_network_data:
                    wan_network_data = parse_input(wan_network_data['policy'])
                    if 'wanNetwork' in wan_network_data:
                        wan_network_policy = parse_input(wan_network_data['wanNetwork'])
                        if 'policy' in wan_network_policy:
                            wan_network_policy = parse_input(wan_network_policy['policy'])
                            if 'enabled' in wan_network_policy:
                                is_wan_network_enabled = True if wan_network_policy.get('enabled', False) else False
                            if 'rules' in wan_network_policy:
                                wan_network_rules_raw = wan_network_policy['rules']
                                for rule in wan_network_rules_raw:
                                    if 'rule' in rule and 'name' in rule['rule']:
                                        wan_network_rules.append(rule['rule']['name'])

            # isFirewallLoggingEnabled is answered only from the audit feed below. A field of that name in the body
            # is never read: the vendor does not send one, so a body that carried it would choose its own answer.
            # A feed that is absent, null, empty, not an object, or has no readable fetchedCount was not measured:
            # the answer stays None. Only a feed that was read with fetchedCount 0 is the measured False.
            if isinstance(audit_data, dict) and 'auditFeed' in audit_data:
                try:
                    audit_logs_raw = parse_input(audit_data['auditFeed'])
                except Exception:
                    audit_logs_raw = None
                if isinstance(audit_logs_raw, dict):
                    fetched_count = read_fetched_count(audit_logs_raw.get('fetchedCount'))
                    if fetched_count is not None:
                        is_firewall_logging_enabled = fetched_count > 0

        is_firewall_enabled_final = is_firewall_enabled or (is_internet_firewall_enabled and is_wan_network_enabled)
        is_firewall_configured = len(internet_firewall_rules) > 0 or len(wan_network_rules) > 0

        additional_findings = []

        # Primary criteria: isFirewallLoggingEnabled. None is Not evaluated: no pass or fail reason is given for it.
        api_errors = []
        if is_firewall_logging_enabled is True:
            pass_reasons.append("Firewall logging is enabled")
        elif is_firewall_logging_enabled is False:
            fail_reasons.append("Firewall logging is not enabled")
            recommendations.append("Enable firewall logging for audit and compliance")
        else:
            api_errors.append(AUDIT_FEED_NOT_READ)

        # Additional finding: isFirewallEnabled
        if is_firewall_enabled_final:
            additional_findings.append({
                "metric": "isFirewallEnabled",
                "status": "pass",
                "reason": "Firewall is enabled"
            })
        else:
            additional_findings.append({
                "metric": "isFirewallEnabled",
                "status": "fail",
                "reason": "Firewall not enabled or not reporting",
                "recommendation": "Enable firewall for network security"
            })

        # Additional finding: isFirewallConfigured
        if is_firewall_configured:
            additional_findings.append({
                "metric": "isFirewallConfigured",
                "status": "pass",
                "reason": f"Firewall configured with {len(internet_firewall_rules)} internet rules and {len(wan_network_rules)} WAN rules"
            })
        else:
            additional_findings.append({
                "metric": "isFirewallConfigured",
                "status": "fail",
                "reason": "No firewall rules configured",
                "recommendation": "Configure firewall rules for proper network security"
            })

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
            additional_findings=additional_findings,
            api_errors=api_errors,
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
                "isFirewallLoggingEnabled": None,
                "isFirewallConfigured": False
            },
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"],
            api_errors=[AUDIT_FEED_NOT_READ]
        )
