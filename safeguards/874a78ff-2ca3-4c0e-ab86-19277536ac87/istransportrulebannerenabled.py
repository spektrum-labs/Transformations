"""
Transformation: isTransportRuleBannerEnabled
Vendor: Microsoft
Category: Email Security / Transport Rules

Evaluates if transport rule banner is enabled by checking for rules with Disclaimer or SubjectPrefix actions.
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
                "transformationId": "isTransportRuleBannerEnabled",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isTransportRuleBannerEnabled"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        transport_rules = data.get("transportRules", [])
        banner_rules = []

        for rule in transport_rules:
            actions = rule.get('Actions', [])
            if actions:
                matching_actions = [action for action in actions if ('Disclaimer' in action or 'SubjectPrefix' in action)]
                if matching_actions:
                    banner_rules.append({
                        'Name': rule.get('Name', 'Unknown'),
                        'State': rule.get('State', 'Unknown'),
                        'Mode': rule.get('Mode', 'Unknown')
                    })

        # Check if any banner rule is enabled
        enabled_rules = [rule for rule in banner_rules if rule['State'] == 'Enabled']
        is_enabled = len(enabled_rules) > 0

        if is_enabled:
            rule_names = [r['Name'] for r in enabled_rules[:3]]
            pass_reasons.append(f"Transport rule banner enabled via {len(enabled_rules)} rule(s): {', '.join(rule_names)}")
        else:
            if len(banner_rules) > 0:
                fail_reasons.append(f"Found {len(banner_rules)} banner rule(s) but none are enabled")
            else:
                fail_reasons.append("No transport rules with Disclaimer or SubjectPrefix actions found")
            recommendations.append("Enable transport rules with banner/disclaimer actions for external email warnings")

        return create_response(
            result={criteriaKey: is_enabled, "totalRules": len(transport_rules), "bannerRulesCount": len(banner_rules)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalRules": len(transport_rules), "bannerRules": len(banner_rules), "enabledBannerRules": len(enabled_rules)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
