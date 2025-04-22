# is_backup_types_scheduled.py

import json

def transform(input):
    """
    Checks if all backup types (RDS automated, RDS manual, EBS) are on a defined schedule.
    Returns: {"isBackupTypesScheduled": bool}
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                return json.loads(input)
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")
    
        data = _parse_input(input).get("response", {}).get("result", _parse_input(input))

        # Automated RDS: scheduled if BackupRetentionPeriod > 0
        dbBackups   = data.get("dbBackups", {})
        resp        = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        result      = resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        container   = result.get("DBInstanceAutomatedBackups", {})
        retention   = 0
        if isinstance(container, dict) and "DBInstanceAutomatedBackup" in container:
            entry = container["DBInstanceAutomatedBackup"]
            retention = int(entry.get("BackupRetentionPeriod", 0))
        scheduled_auto = retention > 0

        # Manual & EBS have no schedule metadata → assume False
        scheduled_manual = False
        scheduled_ebs    = False

        return {"isBackupTypesScheduled": scheduled_auto and scheduled_manual and scheduled_ebs}

    except json.JSONDecodeError:
        return {"isBackupTypesScheduled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}
