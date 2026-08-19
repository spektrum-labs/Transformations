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

    # Exclude the implicit default rule (Meraki auto-appends one with no
    # comment/policy customization and syslog is not configurable on it).
    evaluable_rules = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        comment = (r.get("comment") or "").strip().lower()
        if comment == "default rule":
            continue
        evaluable_rules.append(r)

    total_rules = len(evaluable_rules)
    logged_rules = [r for r in evaluable_rules if r.get("syslogEnabled") is True]
    logged_count = len(logged_rules)

    if total_rules == 0:
        result = {
            "firewallLoggingEnabled": False,
            "totalRules": 0,
            "loggedRules": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No custom L3 firewall rules were found (only the implicit default rule, if any), so per-rule syslog logging cannot be confirmed."],
            recommendations=["Create explicit Layer 3 firewall rules and enable 'Log this rule to syslog' (syslogEnabled=true) on each."],
            input_summary={"totalRules": 0, "loggedRules": 0},
            metadata={"transformationId": "firewallLoggingEnabled", "vendor": "Cisco Meraki MX", "category": "firewalls"},
        )

    all_logged = logged_count == total_rules

    sample_names = []
    for r in evaluable_rules[:5]:
        c = r.get("comment") or "(no comment)"
        sample_names.append(f"{c}:syslogEnabled={r.get('syslogEnabled')}")

    result = {
        "firewallLoggingEnabled": all_logged,
        "totalRules": total_rules,
        "loggedRules": logged_count,
    }

    if all_logged:
        pass_reasons = [
            f"All {total_rules} configured L3 firewall rules (excluding the implicit default rule) have syslogEnabled=true.",
            f"Sample rules inspected: {', '.join(sample_names)}.",
        ]
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary={"totalRules": total_rules, "loggedRules": logged_count},
            metadata={"transformationId": "firewallLoggingEnabled", "vendor": "Cisco Meraki MX", "category": "firewalls"},
        )
    else:
        unlogged = total_rules - logged_count
        fail_reasons = [
            f"{unlogged} of {total_rules} configured L3 firewall rules have syslogEnabled=false or unset (only {logged_count} report syslogEnabled=true).",
            f"Sample rules inspected: {', '.join(sample_names)}.",
        ]
        recommendations = [
            "Enable 'Log this rule to syslog' (syslogEnabled=true) on every custom Layer 3 firewall rule to ensure rule hits are captured."
        ]
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalRules": total_rules, "loggedRules": logged_count},
            metadata={"transformationId": "firewallLoggingEnabled", "vendor": "Cisco Meraki MX", "category": "firewalls"},
        )
