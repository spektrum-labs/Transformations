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

        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # === EVALUATION LOGIC ===
        # GET /api/v1/alert-rules/ returns DRF paginated response
        # Each alert rule has: id, enabled, ruleset_id, channel, logic (object with name)
        # Channel values: prod, beta, testing, ao_only_prod, ao_only_beta, ao_only_testing
        rules = data.get("results", data.get("data", data.get("items", [])))

        if not isinstance(rules, list):
            return create_response(
                result={criteriaKey: False, "enabledRules": 0, "channels": []},
                validation=validation,
                fail_reasons=["Unexpected alert rules response format"],
                recommendations=["Verify the API response contains a list of alert rules"],
                input_summary={"dataType": "non-list"}
            )

        total = len(rules)
        enabled = [r for r in rules if r.get("enabled", False)]
        channels = list({r.get("channel", "unknown") for r in enabled if r.get("channel")})
        rule_names = [r.get("logic", {}).get("name", r.get("name", "unnamed")) for r in enabled]

        result = len(enabled) >= 1
        # === END EVALUATION LOGIC ===

        if result:
            pass_reasons.append(f"{len(enabled)} of {total} alert rule(s) enabled")
            if channels:
                pass_reasons.append(f"Active channels: {', '.join(channels)}")
        else:
            fail_reasons.append(f"No enabled alert rules found (total: {total})")
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
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
