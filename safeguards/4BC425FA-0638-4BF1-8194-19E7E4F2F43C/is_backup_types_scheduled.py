"""
Transformation: isBackupTypesScheduled
Vendor: AWS
Category: Backups / Compliance

Checks if all backup types (RDS automated, RDS manual, EBS) are on a defined schedule.
"""

import json
from datetime import datetime

#: The criterion this file answers; a None value is reported as not measured.
CRITERIA_KEY = "isBackupTypesScheduled"


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
    # Not measured is read off the criterion's value, so every path that leaves it None -- the
    # except branch included -- reaches Token-Service as not evaluated rather than as a gap.
    measured = result.get(CRITERIA_KEY) is not None
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else (api_errors or fail_reasons or transformation_errors
                                               or ["The response could not answer this check, so it was not evaluated."])
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
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


#: The getBackups workflow sections this check reads, each with the describe response it must carry.
SECTIONS = (("dbBackups", "DescribeDBInstanceAutomatedBackupsResponse"),)


def unread_sections(data, sections):
    """The workflow sections that did not come back as a describe response: absent, null or an error
    envelope. A reading that lacks one of them has not looked at that kind of backup."""
    if not isinstance(data, dict):
        return [name for name, response in sections]
    return [name for name, response in sections
            if not (isinstance(data.get(name), dict) and isinstance(data[name].get(response), dict))]

def transform(input):
    criteriaKey = CRITERIA_KEY

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Automated RDS: scheduled if BackupRetentionPeriod > 0
        unread = unread_sections(data, SECTIONS)
        if unread:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["dbBackups did not return a DescribeDBInstanceAutomatedBackups response, so the RDS backup schedule was not read"],
                fail_reasons=["Not measured: " + "dbBackups did not return a DescribeDBInstanceAutomatedBackups response, so the RDS backup schedule was not read"],
                recommendations=["Confirm the AWS credential can call the describe APIs and that each returned a 2xx body."]
            )

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
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
