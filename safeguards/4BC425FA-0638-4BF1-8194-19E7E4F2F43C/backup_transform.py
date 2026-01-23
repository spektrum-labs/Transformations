"""
Transformation: backup_transform
Vendor: AWS
Category: Backups

Evaluates whether backups are enabled for AWS resources including:
- RDS automated backups
- RDS manual snapshots
- EBS volume snapshots
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
                "transformationId": "backup_transform",
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isBackupEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Extract backup data
        db_backups = data.get("dbBackups") or {}
        db_manual_snapshots = data.get("dbManualSnapshots") or {}
        volume_snapshots = data.get("volumeSnapshots") or {}

        # Process RDS Automated Backups
        auto_response = db_backups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_result = auto_response.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_backups_container = auto_result.get("DBInstanceAutomatedBackups", {})

        if isinstance(auto_backups_container, dict):
            auto_backups = auto_backups_container.get("DBInstanceAutomatedBackup", [])
            if isinstance(auto_backups, dict):
                auto_backups = [auto_backups]
        elif isinstance(auto_backups_container, list):
            auto_backups = auto_backups_container
        else:
            auto_backups = []

        automated_backup_count = len(auto_backups) if auto_backups else 0

        # Process RDS Manual Snapshots
        manual_response = db_manual_snapshots.get("DescribeDBSnapshotsResponse", {})
        manual_result = manual_response.get("DescribeDBSnapshotsResult", {})
        manual_snapshots_container = manual_result.get("DBSnapshots", {})

        if isinstance(manual_snapshots_container, dict):
            manual_snapshots = manual_snapshots_container.get("DBSnapshot", [])
            if isinstance(manual_snapshots, dict):
                manual_snapshots = [manual_snapshots]
        elif isinstance(manual_snapshots_container, list):
            manual_snapshots = manual_snapshots_container
        else:
            manual_snapshots = []

        manual_snapshot_count = len(manual_snapshots) if manual_snapshots else 0

        # Process EBS Volume Snapshots
        vol_response = volume_snapshots.get("DescribeSnapshotsResponse", {})
        vol_snapshots_container = vol_response.get("snapshotSet", {})

        if vol_snapshots_container is None:
            volume_snapshot_list = []
        elif isinstance(vol_snapshots_container, dict):
            volume_snapshot_list = vol_snapshots_container.get("item", [])
            if isinstance(volume_snapshot_list, dict):
                volume_snapshot_list = [volume_snapshot_list]
        elif isinstance(vol_snapshots_container, list):
            volume_snapshot_list = vol_snapshots_container
        else:
            volume_snapshot_list = []

        volume_snapshot_count = len(volume_snapshot_list) if volume_snapshot_list else 0

        # Determine overall result
        total_backups = automated_backup_count + manual_snapshot_count + volume_snapshot_count
        is_backup_enabled = total_backups > 0

        if automated_backup_count > 0:
            pass_reasons.append(f"{automated_backup_count} RDS automated backup(s) configured")
        else:
            fail_reasons.append("No RDS automated backups found")
            recommendations.append("Enable automated backups for RDS instances")

        if manual_snapshot_count > 0:
            pass_reasons.append(f"{manual_snapshot_count} RDS manual snapshot(s) available")

        if volume_snapshot_count > 0:
            pass_reasons.append(f"{volume_snapshot_count} EBS volume snapshot(s) available")

        if not is_backup_enabled:
            fail_reasons.append("No backups or snapshots found for any resource type")
            recommendations.append("Implement a backup strategy for your AWS resources")

        return create_response(
            result={
                "isBackupEnabled": is_backup_enabled,
                "automatedBackupCount": automated_backup_count,
                "manualSnapshotCount": manual_snapshot_count,
                "volumeSnapshotCount": volume_snapshot_count,
                "totalBackupCount": total_backups
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "hasDbBackupsData": bool(db_backups),
                "hasDbManualSnapshotsData": bool(db_manual_snapshots),
                "hasVolumeSnapshotsData": bool(volume_snapshots),
                "automatedBackupCount": automated_backup_count,
                "manualSnapshotCount": manual_snapshot_count,
                "volumeSnapshotCount": volume_snapshot_count
            }
        )

    except Exception as e:
        return create_response(
            result={"isBackupEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
