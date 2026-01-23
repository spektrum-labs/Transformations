"""
Transformation: isBackupTypesScheduled
Vendor: Azure
Category: Backup / Data Protection

Checks if all backup types are on a defined schedule.
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
                "transformationId": "isBackupTypesScheduled",
                "vendor": "Azure",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupTypesScheduled"

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

        inner_data = data.get("data", data)
        backupschedules = inner_data.get("rows", [])

        scheduled = False
        protected_items_count = 0

        for schedule in backupschedules:
            if isinstance(schedule, list):
                for item in schedule:
                    if isinstance(item, dict) and 'properties' in item:
                        count = item['properties'].get('protectedItemsCount', 0)
                        if count > 0:
                            scheduled = True
                            protected_items_count += count
            elif isinstance(schedule, dict) and 'properties' in schedule:
                count = schedule['properties'].get('protectedItemsCount', 0)
                if count > 0:
                    scheduled = True
                    protected_items_count += count

        if scheduled:
            pass_reasons.append(f"Backup schedules are configured with {protected_items_count} protected item(s)")
        else:
            fail_reasons.append("No backup schedules with protected items found")
            recommendations.append("Configure backup schedules for all critical resources")

        return create_response(
            result={criteriaKey: scheduled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "schedulesFound": len(backupschedules),
                "protectedItemsCount": protected_items_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
