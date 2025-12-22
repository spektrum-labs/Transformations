# backup_transform.py - Datto BCDR/Backup

import json
import ast

def transform(input):
    """
    Evaluates Datto BCDR backup coverage based on device/agent response data
    and assigns a score from 0 to 100 for each backup safeguard type.
    
    Datto BCDR (formerly Kaseya) provides business continuity and disaster recovery
    including local and cloud backup, instant virtualization, and ransomware protection.

    Parameters:
        input (dict): The JSON data containing Datto BCDR device/agent information.
            Expected structure from Datto REST API:
            {
                "items": [...],  # List of BCDR devices/agents
                "pagination": {...},
                "isBackupConfigured": bool
            }

    Returns:
        dict: A dictionary summarizing the coverage score of each backup safeguard type.
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        # Parse input
        data = _parse_input(input)
        
        # Drill down past response/result wrappers if present
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Initialize configuration status
        isBackupConfigured = data.get("isBackupConfigured", True)
        
        # Datto may use "items", "devices", or "agents" for the list
        devices = (
            data.get("items", []) or
            data.get("devices", []) or
            data.get("agents", []) or
            data.get("data", {}).get("rows", [])
        )
        
        total_devices = len(devices)
        total_servers = 0
        total_workstations = 0
        total_cloud_devices = 0

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
            "Screenshot Verification": 0,
            "Instant Virtualization": 0,
            "Ransomware Protection": 0
        }

        for device in devices:
            # Handle nested device structure
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
            
            # Check for cloud devices
            if device.get("cloudDevice", False) or device.get("isCloud", False):
                total_cloud_devices += 1

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

            # 3. Backup Immutable (Ransomware Shield / Cloud Deletion Defense)
            immutable = (
                device.get("immutableBackup", False) or
                device.get("ransomwareShield", False) or
                device.get("cloudDeletionDefense", False) or
                device.get("retentionLock", False)
            )
            if immutable:
                safeguard_counters["Backup Immutable"] += 1

            # 4. Backup Tested (Screenshot Verification or Restore Tests)
            screenshot_verified = device.get("screenshotVerification", device.get("lastScreenshotStatus", {}))
            restore_tested = device.get("lastRestoreTest", device.get("restoreTestStatus", {}))
            
            if isinstance(screenshot_verified, dict):
                tested = screenshot_verified.get("success", False) or screenshot_verified.get("verified", False)
            elif isinstance(screenshot_verified, bool):
                tested = screenshot_verified
            else:
                tested = str(screenshot_verified).lower() in ["success", "verified", "passed", "true"]
            
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
            if logging_enabled or backup_enabled:  # Assume logging if backup is enabled
                safeguard_counters["Backup Logging"] += 1

            # 7. Critical Systems Protected
            is_critical = (
                device.get("isCritical", False) or
                device.get("criticalSystem", False) or
                device_type in ["server", "windows_server", "linux_server", "virtual_server"]
            )
            if is_critical and backup_enabled:
                safeguard_counters["Critical Systems Protected"] += 1

            # 8. Cloud Backup (Offsite to Datto Cloud)
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
                backup_enabled  # If backup enabled, assume local exists
            )
            if local_backup:
                safeguard_counters["Local Backup"] += 1

            # 10. Screenshot Verification
            if isinstance(screenshot_verified, dict):
                ss_enabled = screenshot_verified.get("enabled", False) or screenshot_verified.get("success", False)
            elif isinstance(screenshot_verified, bool):
                ss_enabled = screenshot_verified
            else:
                ss_enabled = str(screenshot_verified).lower() not in ["", "none", "null", "false"]
            if ss_enabled:
                safeguard_counters["Screenshot Verification"] += 1

            # 11. Instant Virtualization Ready
            instant_virt = (
                device.get("instantVirtualization", False) or
                device.get("localVirtualization", False) or
                device.get("ivrEnabled", False)
            )
            if instant_virt:
                safeguard_counters["Instant Virtualization"] += 1

            # 12. Ransomware Protection
            ransomware = (
                device.get("ransomwareProtection", False) or
                device.get("ransomwareShield", False) or
                device.get("ransomwareDetection", {}).get("enabled", False)
            )
            if ransomware:
                safeguard_counters["Ransomware Protection"] += 1

        # Initialize coverage scores
        coverage_scores = {}
        
        # Calculate total protected assets
        total_protected = total_servers + total_workstations
        if total_protected == 0:
            total_protected = total_devices if total_devices > 0 else 1

        # Calculate scores as percentages
        for key in safeguard_counters:
            if key == "Critical Systems Protected":
                divisor = total_servers if total_servers > 0 else total_devices
            elif key == "Cloud Backup":
                divisor = total_devices
            else:
                divisor = total_devices
            
            coverage_scores[key] = (
                (safeguard_counters[key] / divisor) * 100
                if divisor > 0 else 0
            )

        # Round scores to nearest integer
        for key in coverage_scores:
            coverage_scores[key] = round(coverage_scores[key])

        # Backup-specific boolean outputs
        coverage_scores["isBackupEnabled"] = coverage_scores["Backup Enabled"] > 0
        coverage_scores["isBackupEncrypted"] = coverage_scores["Backup Encrypted"] > 0
        coverage_scores["isBackupImmutable"] = coverage_scores["Backup Immutable"] > 0
        coverage_scores["isBackupTested"] = coverage_scores["Backup Tested"] > 0
        coverage_scores["isBackupTypesScheduled"] = coverage_scores["Backup Scheduled"] > 0
        coverage_scores["isBackupLoggingEnabled"] = coverage_scores["Backup Logging"] > 0
        coverage_scores["isBackupEnabledForCriticalSystems"] = coverage_scores["Critical Systems Protected"] > 0
        coverage_scores["isCloudBackupEnabled"] = coverage_scores["Cloud Backup"] > 0
        coverage_scores["isLocalBackupEnabled"] = coverage_scores["Local Backup"] > 0
        coverage_scores["isScreenshotVerificationEnabled"] = coverage_scores["Screenshot Verification"] > 0
        coverage_scores["isInstantVirtualizationReady"] = coverage_scores["Instant Virtualization"] > 0
        coverage_scores["isRansomwareProtectionEnabled"] = coverage_scores["Ransomware Protection"] > 0
        
        # Configuration status
        coverage_scores["isBackupConfigured"] = isBackupConfigured
        
        # Coverage percentages for compliance
        coverage_scores["requiredCoveragePercentage"] = coverage_scores["Backup Enabled"]
        coverage_scores["requiredConfigurationPercentage"] = coverage_scores["Backup Enabled"]
        
        # Summary statistics
        coverage_scores["totalDevices"] = total_devices
        coverage_scores["totalServers"] = total_servers
        coverage_scores["totalWorkstations"] = total_workstations

        return coverage_scores

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}

