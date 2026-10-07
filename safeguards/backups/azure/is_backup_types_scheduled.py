"""
Transformation: isBackupTypesScheduled
Vendor: Azure Recovery Services / Azure Data Protection
Category: Backup / Data Protection

Checks that backup policies across all Azure Recovery Services vaults and
Backup vaults have schedules configured with protected items assigned.

Data source: Azure Resource Graph query (getBackupSchedules) returning all
backup policies with scheduleType, protectedItemsCount, and schedule details.
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
    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get("isBackupTypesScheduled") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["isBackupTypesScheduled could not be measured from the response"]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else not_measured_reasons
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

        inner_data = data.get("data", data) if isinstance(data, dict) else None
        backupschedules = inner_data.get("rows") if isinstance(inner_data, dict) else None
        if not isinstance(backupschedules, list):
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["isBackupTypesScheduled not evaluated: no Resource Graph 'rows' array in the response"],
                recommendations=["Confirm the principal has at least Reader on every subscription "
                                 "holding a Recovery Services or Backup vault, then re-run the query."]
            )

        # Zero Resource Graph rows is not a measured answer. Resource Graph is RBAC-scoped:
        # a scope the caller cannot read at all answers 403, but a PARTIALLY readable scope
        # answers 200 with only the readable subset and, in Microsoft's words, "without any
        # indication that the result might be partial". So zero rows is equally "there are
        # none" and "the vaults are in a subscription this principal cannot read", and the
        # response carries nothing that tells them apart. See CONTRIBUTING.md, "Azure
        # Resource Graph: zero rows is not a proven empty set".        # A row that DID come back reporting zero protected items is still a measured False
        # below: that vault was read.
        if not backupschedules:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["isBackupTypesScheduled not evaluated: the Resource Graph query returned zero rows, which is also what a subscription this principal cannot read returns"],
                recommendations=["Confirm the principal has at least Reader on every subscription "
                                 "holding a Recovery Services or Backup vault, then re-run the query."]
            )

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
            pass_reasons.append(f"Backup schedules are configured with {protected_items_count} protected items")
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
