"""
Transformation: isBackupEnabled
Vendor: AWS
Category: Backups

Evaluates whether backups are enabled for AWS resources including:
- RDS automated backups
- RDS manual snapshots
- EBS volume snapshots
"""

import json
from datetime import datetime


# ============================================================================
# Response Helpers (inline for RestrictedPython compatibility)
# ============================================================================

def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
    # Check if new enriched format
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    # Legacy format - unwrap common response wrappers
    data = input_data
    if isinstance(data, dict):
        # Handle nested wrappers (e.g., api_response.result)
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):  # Max 3 levels of unwrapping
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break

    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None, transformation_errors=None):
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "1.0",
        "transformationId": "isBackupEnabled",
        "vendor": "AWS",
        "category": "Backups"
    }
    if metadata:
        response_metadata.update(metadata)

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": response_metadata
        }
    }


# ============================================================================
# Transformation Logic
# ============================================================================

def transform(input):
    """
    Evaluates the backup status of AWS resources.

    Checks for:
    - RDS automated backups (DescribeDBInstanceAutomatedBackups)
    - RDS manual snapshots (DescribeDBSnapshots)
    - EBS volume snapshots (DescribeSnapshots)

    Parameters:
        input: Either enriched format {"data": {...}, "validation": {...}}
               or legacy format (raw API response)

    Returns:
        dict: Standardized response with transformedResponse and additionalInfo
    """
    try:
        # Parse input if string/bytes
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        # Extract data and validation (handles both new and legacy formats)
        data, validation = extract_input(input)

        # Early return if schema validation failed
        if validation.get("status") == "failed":
            return create_response(
                result={"isBackupEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))],
                recommendations=["Verify the AWS integration is configured correctly"]
            )

        # Extract backup data with safe defaults (handle explicit None values)
        db_backups = data.get("dbBackups") or {}
        db_manual_snapshots = data.get("dbManualSnapshots") or {}
        volume_snapshots = data.get("volumeSnapshots") or {}

        # Initialize tracking
        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # ----------------------------------------------------------------
        # Process RDS Automated Backups
        # ----------------------------------------------------------------
        auto_response = db_backups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_result = auto_response.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_backups_container = auto_result.get("DBInstanceAutomatedBackups", {})

        # Handle both dict and list formats
        if isinstance(auto_backups_container, dict):
            auto_backups = auto_backups_container.get("DBInstanceAutomatedBackup", [])
            if isinstance(auto_backups, dict):
                auto_backups = [auto_backups]
        elif isinstance(auto_backups_container, list):
            auto_backups = auto_backups_container
        else:
            auto_backups = []

        automated_backup_count = len(auto_backups) if auto_backups else 0

        if automated_backup_count > 0:
            pass_reasons.append(f"{automated_backup_count} RDS automated backup(s) configured")

            # Check retention periods
            low_retention = []
            for backup in auto_backups:
                retention = backup.get("BackupRetentionPeriod", "0")
                db_id = backup.get("DBInstanceIdentifier", "unknown")
                try:
                    retention_days = int(retention)
                    if retention_days < 7:
                        low_retention.append(f"{db_id} ({retention_days} days)")
                except (ValueError, TypeError):
                    pass

            if low_retention:
                recommendations.append(
                    f"Consider increasing backup retention to 7+ days for: {', '.join(low_retention)}"
                )
        else:
            fail_reasons.append("No RDS automated backups found")
            recommendations.append("Enable automated backups for RDS instances")

        # ----------------------------------------------------------------
        # Process RDS Manual Snapshots
        # ----------------------------------------------------------------
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

        if manual_snapshot_count > 0:
            pass_reasons.append(f"{manual_snapshot_count} RDS manual snapshot(s) available")

        # ----------------------------------------------------------------
        # Process EBS Volume Snapshots
        # ----------------------------------------------------------------
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

        if volume_snapshot_count > 0:
            pass_reasons.append(f"{volume_snapshot_count} EBS volume snapshot(s) available")

        # ----------------------------------------------------------------
        # Determine overall result
        # ----------------------------------------------------------------
        total_backups = automated_backup_count + manual_snapshot_count + volume_snapshot_count
        is_backup_enabled = total_backups > 0

        if not is_backup_enabled:
            fail_reasons.append("No backups or snapshots found for any resource type")
            recommendations.append("Implement a backup strategy for your AWS resources")

        # Build response
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

    except json.JSONDecodeError as e:
        return create_response(
            result={"isBackupEnabled": False},
            validation={"status": "error", "errors": [f"Invalid JSON: {str(e)}"], "warnings": []},
            fail_reasons=["Could not parse input as valid JSON"]
        )
    except Exception as e:
        return create_response(
            result={"isBackupEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
