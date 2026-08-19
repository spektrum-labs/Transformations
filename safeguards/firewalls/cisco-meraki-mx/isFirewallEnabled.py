import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    rules = data.get("rules") or []
    if not isinstance(rules, list):
        rules = []

    total_rules = len(rules)

    default_rule = None
    for r in rules:
        if isinstance(r, dict) and isinstance(r.get("comment"), str) and "default rule" in r.get("comment", "").lower():
            default_rule = r
            break
    if default_rule is None and rules:
        default_rule = rules[-1]

    has_configured_rules = total_rules > 0
    allow_count = sum(1 for r in rules if isinstance(r, dict) and r.get("policy") == "allow")
    deny_count = sum(1 for r in rules if isinstance(r, dict) and r.get("policy") == "deny")

    is_firewall_enabled = has_configured_rules

    input_summary = {
        "totalRules": total_rules,
        "allowRules": allow_count,
        "denyRules": deny_count,
        "hasDefaultRule": default_rule is not None,
    }

    if is_firewall_enabled:
        default_policy = default_rule.get("policy") if isinstance(default_rule, dict) else "unknown"
        pass_reasons = [
            f"Network has {total_rules} configured L3 firewall rule(s) ({allow_count} allow, {deny_count} deny) "
            f"including a default rule with policy='{default_policy}', indicating the MX firewall ruleset is active and enforcing policy."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No L3 firewall rules were returned for this network (rules list is empty), so the MX appliance firewall "
            "policy cannot be confirmed as actively enforced."
        ]
        recommendations = [
            "Verify the MX security appliance is online and configure at least a default L3 firewall rule to enforce policy."
        ]

    result = {
        "isFirewallEnabled": is_firewall_enabled,
        "totalRules": total_rules,
        "allowRules": allow_count,
        "denyRules": deny_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isFirewallEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
