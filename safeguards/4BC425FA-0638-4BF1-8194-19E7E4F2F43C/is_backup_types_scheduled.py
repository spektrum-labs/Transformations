"""
Transformation: isBackupTypesScheduled
Vendor: AWS
Category: Backups / Compliance

Checks if all backup types (RDS automated, RDS manual, EBS) are on a defined schedule.
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
                "transformationId": "isBackupTypesScheduled",
                "vendor": "AWS",
                "category": "Backups"
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

        # Automated RDS: scheduled if BackupRetentionPeriod > 0
        db_backups = data.get("dbBackups", {}) if isinstance(data, dict) else {}
        resp = db_backups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        result = resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        container = result.get("DBInstanceAutomatedBackups", {})
        backup_info = container.get("DBInstanceAutomatedBackup", {}) if isinstance(container, dict) else container

        scheduled_auto = True
        retention_values = []
        low_retention_instances = []

        if isinstance(backup_info, list):
            for entry in backup_info:
                retention = int(entry.get("BackupRetentionPeriod", 0))
                retention_values.append(retention)
                if retention == 0:
                    scheduled_auto = False
                    low_retention_instances.append(entry.get("DBInstanceIdentifier", "unknown"))
        elif isinstance(backup_info, dict) and backup_info:
            retention = int(backup_info.get("BackupRetentionPeriod", 0))
            retention_values.append(retention)
            if retention == 0:
                scheduled_auto = False
                low_retention_instances.append(backup_info.get("DBInstanceIdentifier", "unknown"))
        else:
            # No backup info means no scheduled backups
            scheduled_auto = False

        if scheduled_auto and retention_values:
            min_retention = min(retention_values)
            pass_reasons.append(f"Backup schedule configured with minimum {min_retention} day retention")
        elif not scheduled_auto:
            if low_retention_instances:
                fail_reasons.append(f"Backup retention period is 0 for: {', '.join(low_retention_instances)}")
            else:
                fail_reasons.append("No automated backup schedule configured")
            recommendations.append("Configure backup retention period greater than 0 days for all RDS instances")

        return create_response(
            result={criteriaKey: scheduled_auto},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "retentionValues": retention_values,
                "instancesWithZeroRetention": low_retention_instances,
                "hasBackupData": bool(backup_info)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
