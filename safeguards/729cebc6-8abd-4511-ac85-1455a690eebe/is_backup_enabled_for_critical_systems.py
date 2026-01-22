"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: AWS
Category: Backup / Data Protection

Checks that backups are enabled for critical systems.
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
                "transformationId": "isBackupEnabledForCriticalSystems",
                "vendor": "AWS",
                "category": "Backup"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupEnabledForCriticalSystems"

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

        dbBackups = data.get("dbBackups", {})
        dbManualSnapshots = data.get("dbManualSnapshots", {})

        # Automated backups
        auto_resp = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_res = auto_resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_group = auto_res.get("DBInstanceAutomatedBackups", {})
        auto_list = []
        if isinstance(auto_group, dict) and "DBInstanceAutomatedBackup" in auto_group:
            entry = auto_group["DBInstanceAutomatedBackup"]
            auto_list = entry if isinstance(entry, list) else [entry]
        elif isinstance(auto_group, list):
            auto_list = auto_group

        # Manual snapshots
        man_resp = dbManualSnapshots.get("DescribeDBSnapshotsResponse", {})
        man_res = man_resp.get("DescribeDBSnapshotsResult", {})
        man_group = man_res.get("DBSnapshots", {}).get("DBSnapshot", [])
        manual_list = man_group if isinstance(man_group, list) else [man_group] if isinstance(man_group, dict) else []

        # Combine and check
        combined = auto_list + manual_list
        found = len(combined) > 0

        if found:
            pass_reasons.append(f"Backups enabled for critical systems with {len(combined)} backup(s) found")
        else:
            fail_reasons.append("No backups found for critical systems")
            recommendations.append("Enable automated backups for all critical database systems")

        return create_response(
            result={criteriaKey: found},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "automatedBackups": len(auto_list),
                "manualSnapshots": len(manual_list),
                "totalBackups": len(combined)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
