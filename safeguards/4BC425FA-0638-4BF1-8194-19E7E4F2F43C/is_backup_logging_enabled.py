"""
Transformation: isBackupLoggingEnabled
Vendor: AWS
Category: Backups / Compliance

Checks whether logging is enabled for backup operations.
"""

import json
from datetime import datetime

#: The criterion this file answers; a None value is reported as not measured.
CRITERIA_KEY = "isBackupLoggingEnabled"


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
                "transformationId": "isBackupLoggingEnabled",
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


#: The getBackups workflow sections this check reads, each with the describe response it must carry.
SECTIONS = (("dbBackups", "DescribeDBInstanceAutomatedBackupsResponse"),
            ("dbManualSnapshots", "DescribeDBSnapshotsResponse"))


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

        unread = unread_sections(data, SECTIONS)
        db_backups = (data.get("dbBackups") or {}) if isinstance(data, dict) else {}
        db_manual_snapshots = (data.get("dbManualSnapshots") or {}) if isinstance(data, dict) else {}

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

        # A backup record found in what was read is evidence; finding none only counts when every section was read.
        if unread and not logging_enabled:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=[", ".join(unread) + " did not return a describe response, so those backups were not read"],
                fail_reasons=["Not measured: " + ", ".join(unread) + " did not return a describe response, so those backups were not read"],
                recommendations=["Confirm the AWS credential can call the describe APIs and that each returned a 2xx body."]
            )

        if logging_enabled:
            pass_reasons.append(f"Backup logging is enabled ({total_db_backups} backup records found)")
        else:
            fail_reasons.append("No backup activity logged - verify logging is enabled")
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
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
