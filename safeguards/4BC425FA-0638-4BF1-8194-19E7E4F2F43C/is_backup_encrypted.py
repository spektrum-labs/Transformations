"""
Transformation: isBackupEncrypted
Vendor: AWS
Category: Backups / Security

Checks that all backups (RDS automated, RDS manual, EBS) are encrypted at rest.
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
                "transformationId": "isBackupEncrypted",
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


def transform(input):
    auto_enc = True
    man_enc = True
    ebs_enc = True

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isBackupEncrypted": False, "isAutoBackupEncrypted": False, "isManualBackupEncrypted": False, "isEbsBackupEncrypted": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        db_backups = data.get("dbBackups", {})
        db_manual_snapshots = data.get("dbManualSnapshots", {})
        volume_snapshots = data.get("volumeSnapshots", {})

        def _listify(container, key=None):
            if key and isinstance(container, dict) and key in container:
                entry = container[key]
                return entry if isinstance(entry, list) else [entry]
            if isinstance(container, list):
                return container
            return []

        # Automated backups
        auto_resp = db_backups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_res = auto_resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_group = auto_res.get("DBInstanceAutomatedBackups", {})
        auto_list = _listify(auto_group, "DBInstanceAutomatedBackup")

        # Manual snapshots
        man_resp = db_manual_snapshots.get("DescribeDBSnapshotsResponse", {})
        man_res = man_resp.get("DescribeDBSnapshotsResult", {})
        man_group = man_res.get("DBSnapshots", {})
        if isinstance(man_group, dict):
            man_group = man_group.get("DBSnapshot", [])
        manual_list = man_group if isinstance(man_group, list) else [man_group] if isinstance(man_group, dict) else []

        # EBS snapshots
        ebs_resp = volume_snapshots.get("DescribeSnapshotsResponse", {})
        ebs_group = ebs_resp.get("snapshotSet", {})
        if isinstance(ebs_group, dict):
            ebs_group = ebs_group.get("item", [])
        ebs_list = ebs_group if isinstance(ebs_group, list) else [ebs_group] if isinstance(ebs_group, dict) else []

        # Check encryption flags
        unencrypted_auto = []
        for item in auto_list:
            if str(item.get("Encrypted", "")).lower() != "true":
                auto_enc = False
                unencrypted_auto.append(item.get("DBInstanceIdentifier", "unknown"))

        unencrypted_manual = []
        for item in manual_list:
            if str(item.get("Encrypted", "")).lower() != "true":
                man_enc = False
                unencrypted_manual.append(item.get("DBSnapshotIdentifier", "unknown"))

        unencrypted_ebs = []
        for item in ebs_list:
            if str(item.get("encrypted", "")).lower() != "true":
                ebs_enc = False
                unencrypted_ebs.append(item.get("snapshotId", "unknown"))

        all_enc = auto_enc and man_enc and ebs_enc

        if auto_enc and len(auto_list) > 0:
            pass_reasons.append(f"All {len(auto_list)} automated RDS backups are encrypted")
        elif not auto_enc:
            fail_reasons.append(f"{len(unencrypted_auto)} automated RDS backup(s) not encrypted")
            recommendations.append("Enable encryption for RDS automated backups")

        if man_enc and len(manual_list) > 0:
            pass_reasons.append(f"All {len(manual_list)} manual RDS snapshots are encrypted")
        elif not man_enc:
            fail_reasons.append(f"{len(unencrypted_manual)} manual RDS snapshot(s) not encrypted")
            recommendations.append("Enable encryption for RDS manual snapshots")

        if ebs_enc and len(ebs_list) > 0:
            pass_reasons.append(f"All {len(ebs_list)} EBS snapshots are encrypted")
        elif not ebs_enc:
            fail_reasons.append(f"{len(unencrypted_ebs)} EBS snapshot(s) not encrypted")
            recommendations.append("Enable encryption for EBS snapshots")

        return create_response(
            result={
                "isBackupEncrypted": all_enc,
                "isAutoBackupEncrypted": auto_enc,
                "isManualBackupEncrypted": man_enc,
                "isEbsBackupEncrypted": ebs_enc
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "autoBackupCount": len(auto_list),
                "manualSnapshotCount": len(manual_list),
                "ebsSnapshotCount": len(ebs_list),
                "unencryptedAutoCount": len(unencrypted_auto),
                "unencryptedManualCount": len(unencrypted_manual),
                "unencryptedEbsCount": len(unencrypted_ebs)
            }
        )

    except Exception as e:
        return create_response(
            result={"isBackupEncrypted": False, "isAutoBackupEncrypted": auto_enc, "isManualBackupEncrypted": man_enc, "isEbsBackupEncrypted": ebs_enc},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
