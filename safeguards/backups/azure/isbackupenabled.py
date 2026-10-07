"""
Transformation: isBackupEnabled
Vendor: Azure Recovery Services
Category: Backup / Data Protection

Evaluates whether Azure Backup is enabled by checking for diagnostic settings
configurations across Recovery Services vaults and Backup vaults.

Data source: Azure Resource Graph query (getBackupDiagnosticSettings) returning
vault diagnostic settings with log categories and destinations.
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
    value = result.get("isBackupEnabled") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["isBackupEnabled could not be measured from the response"]
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
                "transformationId": "isBackupEnabled",
                "vendor": "Azure",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupEnabled"

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
        rows = inner_data.get("rows") if isinstance(inner_data, dict) else None
        if not isinstance(rows, list):
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["isBackupEnabled not evaluated: no Resource Graph 'rows' array in the response"],
                recommendations=["Confirm the principal has at least Reader on every subscription "
                                 "holding a Recovery Services or Backup vault, then re-run the query."]
            )

        # Zero Resource Graph rows is not a measured answer. Resource Graph is RBAC-scoped:
        # a scope the caller cannot read at all answers 403, but a PARTIALLY readable scope
        # answers 200 with only the readable subset and, in Microsoft's words, "without any
        # indication that the result might be partial". So zero rows is equally "there are
        # none" and "the vaults are in a subscription this principal cannot read", and the
        # response carries nothing that tells them apart. See CONTRIBUTING.md, "Azure
        # Resource Graph: zero rows is not a proven empty set".        # This criterion's only negative signal WAS zero rows, so it can now answer only
        # True or not-measured, exactly as its counterpart in safeguards/729cebc6-.../.
        if not rows:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["isBackupEnabled not evaluated: the Resource Graph query returned zero rows, which is also what a subscription this principal cannot read returns"],
                recommendations=["Confirm the principal has at least Reader on every subscription "
                                 "holding a Recovery Services or Backup vault, then re-run the query."]
            )

        is_enabled = True
        row_count = len(rows)

        if is_enabled:
            pass_reasons.append(f"Backup is enabled with {row_count} backup configurations found")
        else:
            fail_reasons.append("No backup configurations found")
            recommendations.append("Enable backup for database instances")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"backupConfigurations": row_count}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
