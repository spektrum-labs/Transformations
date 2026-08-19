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
    logged_rules = [r for r in rules if isinstance(r, dict) and r.get("syslogEnabled") is True]
    logged_count = len(logged_rules)

    is_enabled = logged_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_rules == 0:
        fail_reasons.append(
            "No L3 firewall rules were returned for this network, so no rule could be confirmed to have syslogEnabled=true."
        )
        recommendations.append(
            "Configure at least one L3 firewall rule with syslogEnabled=true and set an active syslog server on the MX network to receive firewall event logs."
        )
    elif is_enabled:
        sample_comments = [r.get("comment") or r.get("policy") or "unnamed rule" for r in logged_rules[:3]]
        pass_reasons.append(
            f"{logged_count} of {total_rules} L3 firewall rules have syslogEnabled=true (examples: {sample_comments}), indicating a syslog server is configured to receive firewall event logs."
        )
    else:
        fail_reasons.append(
            f"None of the {total_rules} L3 firewall rules have syslogEnabled=true, indicating no syslog server is configured to receive firewall event logs."
        )
        recommendations.append(
            "Enable syslogEnabled on the relevant L3 firewall rules and configure a syslog server for the MX network to capture firewall event logs."
        )

    result = {
        "isFirewallLoggingEnabled": is_enabled,
        "totalRules": total_rules,
        "rulesWithSyslogEnabled": logged_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRules": total_rules, "rulesWithSyslogEnabled": logged_count},
        metadata={
            "transformationId": "isFirewallLoggingEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
