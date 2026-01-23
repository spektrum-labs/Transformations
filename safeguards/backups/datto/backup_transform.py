"""
Transformation: backup_transform (comprehensive)
Vendor: Datto BCDR
Category: Backup / Data Protection

Evaluates Datto BCDR backup coverage based on device/agent response data
and assigns a score from 0 to 100 for each backup safeguard type.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
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
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "backup_transform",
                "vendor": "Datto",
                "category": "Backup"
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

        # Initialize configuration status
        isBackupConfigured = data.get("isBackupConfigured", True) if isinstance(data, dict) else True

        # Datto may use "items", "devices", or "agents" for the list
        devices = []
        if isinstance(data, dict):
            devices = (
                data.get("items", []) or
                data.get("devices", []) or
                data.get("agents", []) or
                data.get("data", {}).get("rows", [])
            )

        total_devices = len(devices)
        total_servers = 0
        total_workstations = 0

        safeguard_counters = {
            "Backup Enabled": 0,
            "Backup Encrypted": 0,
            "Backup Immutable": 0,
            "Backup Tested": 0,
            "Backup Scheduled": 0,
            "Backup Logging": 0,
            "Critical Systems Protected": 0,
            "Cloud Backup": 0,
            "Local Backup": 0,
        }

        for device in devices:
            if isinstance(device, list):
                device = device[0] if len(device) > 0 else {}

            # Get device type
            device_type = (
                device.get("type", "") or
                device.get("deviceType", "") or
                device.get("osType", "")
            )
            if isinstance(device_type, str):
                device_type = device_type.lower()
            else:
                device_type = ""

            # Count device types
            if device_type in ["server", "windows_server", "linux_server", "virtual_server"]:
                total_servers += 1
            elif device_type in ["workstation", "desktop", "laptop", "windows", "macos"]:
                total_workstations += 1

            # Get backup status
            backup_status = device.get("backupStatus", device.get("status", {}))
            if isinstance(backup_status, str):
                backup_status = {"status": backup_status}

            # Get last backup info
            last_backup = device.get("lastBackup", device.get("lastBackupTime", None))
            has_backup = last_backup is not None and last_backup != ""

            # Get protection settings
            protection = device.get("protection", device.get("protectionSettings", {}))
            if isinstance(protection, str):
                protection = {"enabled": protection.lower() == "enabled"}

            # 1. Backup Enabled
            backup_enabled = (
                device.get("backupEnabled", False) or
                device.get("isProtected", False) or
                protection.get("enabled", False) or
                has_backup or
                backup_status.get("status", "").lower() in ["protected", "active", "ok", "success"]
            )
            if backup_enabled:
                safeguard_counters["Backup Enabled"] += 1

            # 2. Backup Encrypted
            encryption = device.get("encryption", device.get("encryptionStatus", {}))
            if isinstance(encryption, bool):
                is_encrypted = encryption
            elif isinstance(encryption, dict):
                is_encrypted = encryption.get("enabled", False) or encryption.get("encrypted", False)
            else:
                is_encrypted = str(encryption).lower() in ["true", "enabled", "encrypted"]
            if is_encrypted:
                safeguard_counters["Backup Encrypted"] += 1

            # 3. Backup Immutable
            immutable = (
                device.get("immutableBackup", False) or
                device.get("ransomwareShield", False) or
                device.get("cloudDeletionDefense", False) or
                device.get("retentionLock", False)
            )
            if immutable:
                safeguard_counters["Backup Immutable"] += 1

            # 4. Backup Tested
            screenshot_verified = device.get("screenshotVerification", device.get("lastScreenshotStatus", {}))
            restore_tested = device.get("lastRestoreTest", device.get("restoreTestStatus", {}))

            tested = False
            if isinstance(screenshot_verified, dict):
                tested = screenshot_verified.get("success", False) or screenshot_verified.get("verified", False)
            elif isinstance(screenshot_verified, bool):
                tested = screenshot_verified
            elif isinstance(screenshot_verified, str):
                tested = screenshot_verified.lower() in ["success", "verified", "passed", "true"]

            if isinstance(restore_tested, dict):
                tested = tested or restore_tested.get("success", False)
            elif restore_tested:
                tested = True

            if tested:
                safeguard_counters["Backup Tested"] += 1

            # 5. Backup Scheduled
            schedule = device.get("schedule", device.get("backupSchedule", {}))
            if isinstance(schedule, dict):
                scheduled = schedule.get("enabled", False) or bool(schedule.get("frequency"))
            elif schedule:
                scheduled = True
            else:
                scheduled = device.get("scheduledBackup", False)
            if scheduled:
                safeguard_counters["Backup Scheduled"] += 1

            # 6. Backup Logging
            logging_enabled = (
                device.get("loggingEnabled", False) or
                device.get("alertsEnabled", False) or
                device.get("notifications", {}).get("enabled", False)
            )
            if logging_enabled or backup_enabled:
                safeguard_counters["Backup Logging"] += 1

            # 7. Critical Systems Protected
            is_critical = (
                device.get("isCritical", False) or
                device.get("criticalSystem", False) or
                device_type in ["server", "windows_server", "linux_server", "virtual_server"]
            )
            if is_critical and backup_enabled:
                safeguard_counters["Critical Systems Protected"] += 1

            # 8. Cloud Backup
            cloud_backup = (
                device.get("cloudBackupEnabled", False) or
                device.get("offsiteBackup", False) or
                device.get("cloudSync", {}).get("enabled", False)
            )
            if cloud_backup:
                safeguard_counters["Cloud Backup"] += 1

            # 9. Local Backup
            local_backup = (
                device.get("localBackupEnabled", False) or
                device.get("localBackup", False) or
                backup_enabled
            )
            if local_backup:
                safeguard_counters["Local Backup"] += 1

        # Calculate scores as percentages
        coverage_scores = {}
        for key in safeguard_counters:
            if key == "Critical Systems Protected":
                divisor = total_servers if total_servers > 0 else total_devices
            else:
                divisor = total_devices

            coverage_scores[key] = round(
                (safeguard_counters[key] / divisor) * 100
                if divisor > 0 else 0
            )

        # Backup-specific boolean outputs
        coverage_scores["isBackupEnabled"] = coverage_scores["Backup Enabled"] > 0
        coverage_scores["isBackupEncrypted"] = coverage_scores["Backup Encrypted"] > 0
        coverage_scores["isBackupImmutable"] = coverage_scores["Backup Immutable"] > 0
        coverage_scores["isBackupTested"] = coverage_scores["Backup Tested"] > 0
        coverage_scores["isBackupTypesScheduled"] = coverage_scores["Backup Scheduled"] > 0
        coverage_scores["isBackupLoggingEnabled"] = coverage_scores["Backup Logging"] > 0
        coverage_scores["isBackupEnabledForCriticalSystems"] = coverage_scores["Critical Systems Protected"] > 0
        coverage_scores["isBackupConfigured"] = isBackupConfigured
        coverage_scores["requiredCoveragePercentage"] = coverage_scores["Backup Enabled"]

        # Summary statistics
        coverage_scores["totalDevices"] = total_devices
        coverage_scores["totalServers"] = total_servers
        coverage_scores["totalWorkstations"] = total_workstations

        # Build pass/fail reasons
        if coverage_scores["isBackupEnabled"]:
            pass_reasons.append(f"Backup enabled for {safeguard_counters['Backup Enabled']}/{total_devices} devices ({coverage_scores['Backup Enabled']}%)")
        else:
            fail_reasons.append("No devices with backup enabled")
            recommendations.append("Enable backup protection for all Datto BCDR devices")

        if coverage_scores["Backup Encrypted"] > 0:
            pass_reasons.append(f"Encryption enabled for {safeguard_counters['Backup Encrypted']} device(s)")

        if coverage_scores["Backup Immutable"] > 0:
            pass_reasons.append(f"Immutable backup enabled for {safeguard_counters['Backup Immutable']} device(s)")

        return create_response(
            result=coverage_scores,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDevices": total_devices,
                "totalServers": total_servers,
                "totalWorkstations": total_workstations,
                "safeguardCounters": safeguard_counters
            }
        )

    except Exception as e:
        return create_response(
            result={"isBackupEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
