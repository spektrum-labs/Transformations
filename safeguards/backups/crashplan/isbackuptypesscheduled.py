# isbackuptypesscheduled.py - CrashPlan

import json
import ast

def transform(input):
    """
    Analyzes backup set configurations to validate scheduled backup frequency settings.
    CrashPlan uses continuous backup by default but can have scheduled frequencies.

    Parameters:
        input (dict): The JSON data from CrashPlan listBackupSets endpoint.

    Returns:
        dict: A dictionary indicating if backup schedules are configured.
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

        # Get backup sets data
        backup_sets = (
            data.get("backupSets", []) or
            data.get("sets", []) or
            data.get("data", []) or
            data.get("items", [])
        )

        total_sets = 0
        active_sets = 0
        scheduled_sets = 0
        continuous_sets = 0
        schedule_types = set()

        if isinstance(backup_sets, list):
            total_sets = len(backup_sets)

            for backup_set in backup_sets:
                # Check if backup set is active
                is_active = backup_set.get("active", True)
                status = backup_set.get("status", "").lower()

                if is_active or status in ["active", "enabled"]:
                    active_sets += 1

                    # Check backup frequency/schedule
                    frequency = backup_set.get("frequency", backup_set.get("backupFrequency", ""))
                    schedule = backup_set.get("schedule", {})
                    backup_config = backup_set.get("backupConfig", {})

                    # CrashPlan can run continuously or on schedule
                    is_continuous = False
                    is_scheduled = False

                    # Check for continuous backup
                    if frequency:
                        freq_lower = str(frequency).lower()
                        if "continuous" in freq_lower or "real-time" in freq_lower:
                            is_continuous = True
                            continuous_sets += 1
                            schedule_types.add("continuous")
                        else:
                            is_scheduled = True
                            scheduled_sets += 1
                            schedule_types.add(freq_lower)

                    # Check schedule object
                    if schedule:
                        schedule_type = schedule.get("type", schedule.get("frequency", ""))
                        if schedule_type:
                            is_scheduled = True
                            scheduled_sets += 1
                            schedule_types.add(str(schedule_type).lower())

                    # Check backup config for frequency
                    if backup_config:
                        config_frequency = backup_config.get("frequency", "")
                        version_frequency = backup_config.get("versionFrequency", "")
                        if config_frequency or version_frequency:
                            is_scheduled = True
                            if not is_continuous:
                                scheduled_sets += 1

                    # If no explicit schedule but set is active, assume continuous (CrashPlan default)
                    if not is_continuous and not is_scheduled:
                        continuous_sets += 1
                        schedule_types.add("continuous")

        elif data.get("totalCount"):
            total_sets = data.get("totalCount", 0)
            active_sets = total_sets
            continuous_sets = total_sets
            schedule_types.add("continuous")

        # CrashPlan is considered to have scheduled backups if:
        # - Has continuous backup enabled (default behavior), OR
        # - Has explicit schedule configurations
        is_scheduled = active_sets > 0 and (continuous_sets > 0 or scheduled_sets > 0)

        return {
            "isBackupTypesScheduled": is_scheduled,
            "totalBackupSets": total_sets,
            "activeBackupSets": active_sets,
            "continuousBackupSets": continuous_sets,
            "scheduledBackupSets": scheduled_sets,
            "scheduleTypes": list(schedule_types)
        }

    except json.JSONDecodeError:
        return {"isBackupTypesScheduled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}
