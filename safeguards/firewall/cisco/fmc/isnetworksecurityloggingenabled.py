"""
Transformation: isNetworkSecurityLoggingEnabled
Vendor: Cisco FMC  |  Category: Network Security / Firewall
Evaluates: Whether access control policy rules have logging enabled.

Data source: FMC REST API
  - GET /api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies (items[])
  - GET .../accesspolicies/{id}/accessrules?expanded=true (accessRules[])

FMC access rules have these logging fields:
  - logBegin (bool): Log at connection start
  - logEnd (bool): Log at connection end
  - sendEventsToFMC (bool): Send events to FMC for analysis

A rule is considered logged if logBegin or logEnd is true AND sendEventsToFMC is true.
Network security logging is enabled when all enabled rules have logging configured.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isNetworkSecurityLoggingEnabled", "vendor": "Cisco FMC", "category": "Network Security"}
        }
    }


def to_bool(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


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


def is_rule_logged(rule):
    """Check if an access rule has adequate logging configured."""
    log_begin = to_bool(rule.get("logBegin", False))
    log_end = to_bool(rule.get("logEnd", False))
    send_to_fmc = to_bool(rule.get("sendEventsToFMC", False))

    has_logging = log_begin or log_end
    has_destination = send_to_fmc

    # Syslog can also be configured via logFiles or syslogConfig
    if not has_destination:
        syslog = rule.get("syslogConfig")
        if isinstance(syslog, dict) and syslog.get("id"):
            has_destination = True

    return has_logging and has_destination


def evaluate(data):
    """Evaluate whether access control rules have logging enabled."""
    try:
        access_rules = extract_access_rules(data)

        if not access_rules:
            # Check if data itself contains rule-like items
            if isinstance(data, dict):
                items = data.get("items", [])
                if isinstance(items, list):
                    access_rules = items
            elif isinstance(data, list):
                access_rules = data

        if not access_rules:
            return {"isNetworkSecurityLoggingEnabled": False, "error": "No access rules found to evaluate logging"}

        # Only evaluate enabled rules
        enabled_rules = []
        for rule in access_rules:
            if not isinstance(rule, dict):
                continue
            enabled = rule.get("enabled")
            if enabled is None:
                enabled = True
            if to_bool(enabled):
                enabled_rules.append(rule)

        if not enabled_rules:
            return {"isNetworkSecurityLoggingEnabled": False, "error": "No enabled access rules found"}

        logged_rules = []
        unlogged_rules = []

        for rule in enabled_rules:
            name = rule.get("name", "Unknown")
            if is_rule_logged(rule):
                logged_rules.append(name)
            else:
                unlogged_rules.append(name)

        all_logged = len(unlogged_rules) == 0 and len(logged_rules) > 0

        findings = []
        findings.append(f"{len(logged_rules)} of {len(enabled_rules)} enabled rules have logging configured")
        if unlogged_rules:
            findings.append(f"Rules without logging: {', '.join(unlogged_rules[:10])}")

        return {
            "isNetworkSecurityLoggingEnabled": all_logged,
            "totalEnabledRules": len(enabled_rules),
            "loggedRules": len(logged_rules),
            "unloggedRules": len(unlogged_rules),
            "unloggedRuleNames": unlogged_rules[:20],
            "findings": findings
        }
    except Exception as e:
        return {"isNetworkSecurityLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isNetworkSecurityLoggingEnabled"
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
            logged = eval_result.get("loggedRules", 0)
            total = eval_result.get("totalEnabledRules", 0)
            pass_reasons.append(f"All {logged}/{total} enabled rules have logging configured")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            unlogged = eval_result.get("unloggedRules", 0)
            if unlogged:
                fail_reasons.append(f"{unlogged} enabled rule(s) lack logging")
            recommendations.append("Enable logBegin or logEnd and sendEventsToFMC on all access control rules")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalEnabledRules": extra_fields.get("totalEnabledRules", 0), "loggedRules": extra_fields.get("loggedRules", 0)},
            additional_findings=eval_result.get("findings", [])
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
