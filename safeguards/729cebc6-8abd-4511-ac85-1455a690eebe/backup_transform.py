"""
Transformation: isBackupEnabled
Vendor: AWS
Category: Backup / Data Protection

Evaluates whether any backups exist across RDS automated, RDS manual, or EBS snapshots.
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
                "transformationId": "isBackupEnabled",
                "vendor": "AWS",
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

        # Extract each backup category
        dbBackups = data.get("dbBackups", {})
        dbManualSnapshots = data.get("dbManualSnapshots", {})
        volumeSnapshots = data.get("volumeSnapshots", {})

        # Automated RDS
        auto_resp = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_res = auto_resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_group = auto_res.get("DBInstanceAutomatedBackups", [])
        if isinstance(auto_group, dict):
            auto_group = [auto_group]
        automated = auto_group

        # Manual RDS
        man_resp = dbManualSnapshots.get("DescribeDBSnapshotsResponse", {})
        man_res = man_resp.get("DescribeDBSnapshotsResult", {})
        man_group = man_res.get("DBSnapshots", {}).get("DBSnapshot", [])
        if isinstance(man_group, dict):
            man_group = [man_group]
        manual = man_group

        # EBS snapshots
        ebs_resp = volumeSnapshots.get("DescribeSnapshotsResponse", {})
        ebs_group = ebs_resp.get("snapshotSet", {}).get("item", [])
        if isinstance(ebs_group, dict):
            ebs_group = [ebs_group]
        ebs = ebs_group

        is_enabled = bool(automated or manual or ebs)

        if is_enabled:
            details = []
            if automated:
                details.append(f"{len(automated)} RDS automated backup(s)")
            if manual:
                details.append(f"{len(manual)} RDS manual snapshot(s)")
            if ebs:
                details.append(f"{len(ebs)} EBS snapshot(s)")
            pass_reasons.append(f"Backups enabled: {', '.join(details)}")
        else:
            fail_reasons.append("No backups found (RDS automated, RDS manual, or EBS)")
            recommendations.append("Enable automated backups for RDS instances and EBS volumes")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "automatedRdsBackups": len(automated),
                "manualRdsSnapshots": len(manual),
                "ebsSnapshots": len(ebs)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
