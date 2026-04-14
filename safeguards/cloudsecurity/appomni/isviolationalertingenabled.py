"""
Transformation: isViolationAlertingEnabled
Vendor: AppOmni  |  Category: Cloud Security
Evaluates: At least one alert rule is configured and enabled in AppOmni
API: GET /api/v1/alert-rules/
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


def str_to_bool(val):
    """Handle AppOmni string booleans ('True', 'False', 'None')."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return False


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isViolationAlertingEnabled", "vendor": "AppOmni", "category": "Cloud Security"}
        }
    }


def transform(input):
    criteriaKey = "isViolationAlertingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        # AppOmni /alert-rules/ returns a paginated dict or bare list
        rules = []
        if isinstance(data, list):
            rules = [item for item in data if isinstance(item, dict)]
        elif isinstance(data, dict):
            candidate = data.get("results", data.get("data", data.get("items", None)))
            if isinstance(candidate, list):
                rules = [item for item in candidate if isinstance(item, dict)]
            else:
                rules = [data]

        total = len(rules)

        # A rule is enabled if its enabled field is true (string or bool)
        enabled = []
        for r in rules:
            if not isinstance(r, dict):
                continue
            if str_to_bool(r.get("enabled", False)):
                enabled.append(r)

        # Deduplicate channels
        seen_channels = {}
        channels = []
        for r in enabled:
            ch = r.get("channel", "")
            if ch and ch != "None" and ch not in seen_channels:
                seen_channels[ch] = True
                channels.append(ch)

        rule_names = []
        for r in enabled:
            logic = r.get("logic", None)
            if isinstance(logic, dict):
                name = logic.get("name", r.get("name", "unnamed"))
            else:
                name = r.get("name", "unnamed")
            # Handle string "None"
            if not isinstance(name, str) or name == "None":
                name = "unnamed"
            rule_names.append(name)

        result = len(enabled) >= 1

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result:
            ch_str = ""
            for idx in range(len(channels)):
                if idx > 0:
                    ch_str = ch_str + ", "
                ch_str = ch_str + str(channels[idx])
            pass_reasons.append(str(len(enabled)) + " of " + str(total) + " alert rule(s) enabled")
            if channels:
                pass_reasons.append("Active channels: " + ch_str)
        else:
            fail_reasons.append("No enabled alert rules found (total: " + str(total) + ")")
            recommendations.append("Configure and enable at least one alert rule in AppOmni for violation alerting")

        return create_response(
            result={criteriaKey: result, "enabledRules": len(enabled), "totalRules": total, "channels": channels, "ruleNames": rule_names},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalRules": total, "enabledRules": len(enabled), "channels": channels}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
