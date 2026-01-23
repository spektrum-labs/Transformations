"""
Transformation: isBackupLoggingEnabled
Vendor: AWS
Category: Backups / Compliance

Checks whether logging is enabled for backup operations.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupLoggingEnabled",
                "vendor": "AWS",
                "category": "Backups"
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

        db_backups = data.get("dbBackups", {}) if isinstance(data, dict) else {}
        db_manual_snapshots = data.get("dbManualSnapshots", {}) if isinstance(data, dict) else {}

        # Check for Automated DB Backups
        response = db_backups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        result = response.get("DescribeDBInstanceAutomatedBackupsResult", {})
        automated_backups = result.get("DBInstanceAutomatedBackups", [])

        if isinstance(automated_backups, dict):
            automated_backups = [automated_backups]

        total_auto_backups = len(automated_backups) if automated_backups else 0

        # Check for Manual DB Backups
        response = db_manual_snapshots.get("DescribeDBSnapshotsResponse", {})
        result = response.get("DescribeDBSnapshotsResult", {})
        manual_backups = result.get("DBSnapshots", {})
        manual_backups = manual_backups.get("DBSnapshot", []) if isinstance(manual_backups, dict) else manual_backups

        if isinstance(manual_backups, dict):
            manual_backups = [manual_backups]

        total_manual_backups = len(manual_backups) if manual_backups else 0

        total_db_backups = total_auto_backups + total_manual_backups
        logging_enabled = total_db_backups > 0

        if logging_enabled:
            pass_reasons.append(f"Backup logging is enabled ({total_db_backups} backup records found)")
        else:
            fail_reasons.append("No backup records found - logging may not be enabled")
            recommendations.append("Enable AWS Backup logging and CloudTrail for backup events")

        return create_response(
            result={criteriaKey: logging_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "automatedBackupCount": total_auto_backups,
                "manualBackupCount": total_manual_backups,
                "totalBackupRecords": total_db_backups
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
