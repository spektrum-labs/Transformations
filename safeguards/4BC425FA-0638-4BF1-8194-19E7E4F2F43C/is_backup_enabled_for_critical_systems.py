# is_backup_enabled_for_critical_systems.py

import json

def transform(input):
    """
    Checks that backups are enabled for critical systems
    Returns: {"isBackupEnabledForCriticalSystems": bool}
    """
    try:
        data = _parse_input(input).get("response", {}).get("result", _parse_input(input))

        dbBackups         = data.get("dbBackups", {})
        dbManualSnapshots = data.get("dbManualSnapshots", {})

        # Automated backups
        auto_resp  = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_res   = auto_resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_group = auto_res.get("DBInstanceAutomatedBackups", {})
        auto_list  = []
        if isinstance(auto_group, dict) and "DBInstanceAutomatedBackup" in auto_group:
            entry = auto_group["DBInstanceAutomatedBackup"]
            auto_list = entry if isinstance(entry, list) else [entry]
        elif isinstance(auto_group, list):
            auto_list = auto_group

        # Manual snapshots
        man_resp   = dbManualSnapshots.get("DescribeDBSnapshotsResponse", {})
        man_res    = man_resp.get("DescribeDBSnapshotsResult", {})
        man_group  = man_res.get("DBSnapshots", {}).get("DBSnapshot", [])
        manual_list = man_group if isinstance(man_group, list) else [man_group] if isinstance(man_group, dict) else []

        # Combine and check
        combined = auto_list + manual_list
        #TODO: Define Critical Systems
        found = len(combined) > 0

        return {"isBackupEnabledForCriticalSystems": found}

    except json.JSONDecodeError:
        return {"isBackupEnabledForCriticalSystems": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}


def _parse_input(input):
    if isinstance(input, str):
        return json.loads(input)
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")
