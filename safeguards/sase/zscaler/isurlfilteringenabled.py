"""
Transformation: isURLFilteringEnabled
Vendor: Zscaler ZIA
Category: SASE / URL Filtering

Evaluates if URL filtering policies are configured and active in Zscaler ZIA.
Checks for the presence of web application rules and URL filtering configurations.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "isURLFilteringEnabled",
                "vendor": "Zscaler ZIA",
                "category": "SASE"
            }
        }
    }


def transform(input):
    criteriaKey = "isURLFilteringEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "rulesCount": 0, "enabledRulesCount": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        isURLFilteringEnabled = False
        rules_count = 0
        enabled_rules_count = 0
        block_rules_count = 0

        # Handle raw list input (API returns array of rules directly)
        url_rules = None
        if isinstance(data, list):
            url_rules = data
        elif isinstance(data, dict):
            url_rules = data.get('urlFilteringRules', data.get('responseData', None))

            # Check for URL categories or other URL filtering indicators
            url_categories = data.get('urlCategories', [])
            if isinstance(url_categories, list) and len(url_categories) > 0:
                isURLFilteringEnabled = True

        # Process rules list (from raw input or dict key)
        if isinstance(url_rules, list):
            rules_count = len(url_rules)

            if rules_count > 0:
                isURLFilteringEnabled = True

                # Count enabled rules and block rules
                for rule in url_rules:
                    if not isinstance(rule, dict):
                        continue
                    state = rule.get('state', rule.get('status', '')).upper()

                    if state:
                        if state == 'ENABLED':
                            enabled_rules_count += 1
                    elif rule.get('enabled', True):
                        enabled_rules_count += 1

                    action = rule.get('action', '')
                    if isinstance(action, str) and action.upper() == 'BLOCK':
                        block_rules_count += 1

        if block_rules_count > 0:
            additional_findings.append({
                "metric": "blockRulesCount",
                "status": "pass",
                "reason": f"{block_rules_count} BLOCK rules configured for URL filtering"
            })

        if isURLFilteringEnabled:
            pass_reasons.append(f"URL filtering is enabled with {rules_count} rules ({enabled_rules_count} active)")
        else:
            fail_reasons.append("No URL filtering rules are configured")
            recommendations.append("Configure URL filtering policies in Zscaler ZIA to control web access")

        return create_response(
            result={criteriaKey: isURLFilteringEnabled, "rulesCount": rules_count, "enabledRulesCount": enabled_rules_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalRules": rules_count,
                "enabledRules": enabled_rules_count,
                "blockRules": block_rules_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "rulesCount": 0, "enabledRulesCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
