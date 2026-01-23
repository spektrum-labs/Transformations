"""
Transformation: isBackupLoggingEnabled
Vendor: Azure
Category: Backup / Logging

Checks whether logging is enabled and sending to SIEM if possible.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupLoggingEnabled",
                "vendor": "Azure",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupLoggingEnabled"

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

        # Check for diagnostic settings in data rows
        logging_enabled = False
        log_categories_found = []

        inner_data = data.get("data", data)
        if 'rows' in inner_data:
            rows = inner_data.get("rows", [])
            for row in rows:
                if isinstance(row, list):
                    for item in row:
                        if isinstance(item, dict):
                            if 'hasDiagnosticSettings' in item:
                                if item['hasDiagnosticSettings'] and 'logCategories' in item and item['logCategories']:
                                    logging_enabled = True
                                    log_categories_found.extend(item.get('logCategories', []))

        if logging_enabled:
            pass_reasons.append(f"Backup logging is enabled with diagnostic settings configured")
            if log_categories_found:
                pass_reasons.append(f"Log categories: {', '.join(log_categories_found[:5])}")
        else:
            fail_reasons.append("Backup logging is not enabled or diagnostic settings not configured")
            recommendations.append("Enable diagnostic settings for backup resources and configure log categories")

        return create_response(
            result={criteriaKey: logging_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "loggingEnabled": logging_enabled,
                "logCategoriesCount": len(log_categories_found)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
