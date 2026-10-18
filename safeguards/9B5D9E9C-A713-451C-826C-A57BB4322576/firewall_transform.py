"""
Transformation: firewall_transform
Vendor: Firewall (Cato Networks)
Category: Network Security / Firewall

Evaluates if Firewalls are set up properly including internet firewall and WAN network rules.

isFirewallLoggingEnabled is answered only from the audit feed. A feed that was read with fetchedCount above zero is True
and one read with fetchedCount 0 is the measured False. A feed that is absent, null, empty, not an object, or has no
readable fetchedCount was not measured: the answer is None with a data-collection error, which is Not evaluated. A field
of that name in the body is never read.

isFirewallEnabled and isFirewallConfigured are answered from the two policy layers (internet firewall, WAN network). A
layer is read only when its policy object is there and its enabled flag is a boolean or the text "true" or "false"
(any case, any spacing); any other value (a number, "maybe", null, a list) leaves the layer unread, and an unread layer
contributes no rules. Only a measured read may answer False. isFirewallEnabled is the AND of the two layers: True with
an unread layer is None, False with an unread layer is the measured False. isFirewallConfigured is the OR: a rule seen
in a read layer is True, and no rule with an unread layer (or a rules value that is not a list, which is skipped) is
None. Neither layer read: both None with a data-collection error. A failed validation and an exception answer None for
all three keys with a data-collection error.
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
LAYERS_NOT_READ = ("A firewall policy layer (internet firewall or WAN network) could not be read, so a firewall answer "
                   "that needs it was not evaluated")
VALIDATION_FAILED = "Input validation failed, so no firewall answer was evaluated"
PROCESSING_FAILED = "The firewall response could not be processed, so no firewall answer was evaluated"
MAX_ERROR_TEXT = 200


def read_enabled(value):
    """True or False for a boolean or the text "true" or "false" (any case, any spacing), else None (unreadable).

    A number, "maybe", "yes", null, an empty string, a list and an object are unreadable: they never read as enabled."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    return None


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
    internet_layer_read = False
    wan_layer_read = False
    internet_rules_read = False
    wan_rules_read = False
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
                result={"isFirewallEnabled": None, "isFirewallLoggingEnabled": None, "isFirewallConfigured": None},
                validation=validation,
                fail_reasons=["Input validation failed"],
                api_errors=[VALIDATION_FAILED]
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
                            internet_flag = read_enabled(firewall_policy.get('enabled'))
                            if internet_flag is not None:
                                internet_layer_read = True
                                is_internet_firewall_enabled = internet_flag
                                # No rules key is no rules. A rules value that is not a list (null, text) leaves the
                                # layer's rules unread: they are skipped, and the layer never answers False for Configured.
                                internet_firewall_rules_raw = firewall_policy['rules'] if 'rules' in firewall_policy else []
                                if isinstance(internet_firewall_rules_raw, list):
                                    internet_rules_read = True
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
                            wan_flag = read_enabled(wan_network_policy.get('enabled'))
                            if wan_flag is not None:
                                wan_layer_read = True
                                is_wan_network_enabled = wan_flag
                                wan_network_rules_raw = wan_network_policy['rules'] if 'rules' in wan_network_policy else []
                                if isinstance(wan_network_rules_raw, list):
                                    wan_rules_read = True
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

        # Only a measured read may answer False. Enabled is the AND of the two layers: a layer read as disabled makes it
        # False, both read and enabled make it True, and an unread layer beside an enabled one leaves it None.
        # Configured is the OR: a rule seen in a read layer makes it True, no rule with both layers' rules read makes it
        # False, and no rule with a layer or its rules unread leaves it None.
        is_firewall_enabled_final = None
        if (internet_layer_read and not is_internet_firewall_enabled) or (wan_layer_read and not is_wan_network_enabled):
            is_firewall_enabled_final = False
        elif internet_layer_read and wan_layer_read:
            is_firewall_enabled_final = True
        is_firewall_configured = None
        if len(internet_firewall_rules) > 0 or len(wan_network_rules) > 0:
            is_firewall_configured = True
        elif internet_rules_read and wan_rules_read:
            is_firewall_configured = False

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

        if is_firewall_enabled_final is None or is_firewall_configured is None:
            api_errors.append(LAYERS_NOT_READ)

        # Additional finding: isFirewallEnabled (none when it was not evaluated)
        if is_firewall_enabled_final is None:
            pass
        elif is_firewall_enabled_final:
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

        # Additional finding: isFirewallConfigured (none when it was not evaluated)
        if is_firewall_configured is None:
            pass
        elif is_firewall_configured:
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
                "isFirewallEnabled": None,
                "isFirewallLoggingEnabled": None,
                "isFirewallConfigured": None
            },
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)[:MAX_ERROR_TEXT]],
            fail_reasons=[f"Transformation error: {str(e)[:MAX_ERROR_TEXT]}"],
            api_errors=[PROCESSING_FAILED]
        )
