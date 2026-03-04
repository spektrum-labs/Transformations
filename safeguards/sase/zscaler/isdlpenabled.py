"""
Transformation: isDLPEnabled
Vendor: Zscaler ZIA
Category: SASE / Data Loss Prevention

Evaluates if Data Loss Prevention (DLP) policies are configured in Zscaler ZIA.
Checks for the presence of DLP rules, dictionaries, and engine configuration.
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
                "transformationId": "isDLPEnabled",
                "vendor": "Zscaler ZIA",
                "category": "SASE"
            }
        }
    }


def transform(input):
    criteriaKey = "isDLPEnabled"

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

        isDLPEnabled = False
        rules_count = 0
        enabled_rules_count = 0

        # Handle raw list input (API returns array of rules directly)
        dlp_rules = None
        if isinstance(data, list):
            dlp_rules = data
        elif isinstance(data, dict):
            dlp_rules = data.get('dlpRules', data.get('responseData', None))

            # Check for DLP dictionaries (indicates DLP is configured)
            dlp_dictionaries = data.get('dlpDictionaries', [])
            if isinstance(dlp_dictionaries, list) and len(dlp_dictionaries) > 0:
                isDLPEnabled = True

            # Check for DLP engines or policies
            if data.get('dlpEnabled') or data.get('dlpEngineEnabled'):
                isDLPEnabled = True

        # Process rules list (from raw input or dict key)
        if isinstance(dlp_rules, list):
            rules_count = len(dlp_rules)

            if rules_count > 0:
                isDLPEnabled = True

                # Count enabled rules
                for rule in dlp_rules:
                    if not isinstance(rule, dict):
                        continue
                    state = rule.get('state', rule.get('status', '')).upper()

                    if state:
                        if state == 'ENABLED':
                            enabled_rules_count += 1
                    elif rule.get('enabled', True):
                        enabled_rules_count += 1

        if isDLPEnabled:
            pass_reasons.append(f"DLP is enabled with {rules_count} rules ({enabled_rules_count} active)")
        else:
            fail_reasons.append("No DLP policies are configured")
            recommendations.append("Configure Data Loss Prevention policies in Zscaler ZIA to protect sensitive data")

        return create_response(
            result={criteriaKey: isDLPEnabled, "rulesCount": rules_count, "enabledRulesCount": enabled_rules_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalRules": rules_count,
                "enabledRules": enabled_rules_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "rulesCount": 0, "enabledRulesCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
