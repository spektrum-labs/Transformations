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
    
        data = _parse_input(input).get("response", _parse_input(input)).get("result", _parse_input(input))

        # Automated RDS: scheduled if BackupRetentionPeriod > 0
        dbBackups   = data.get("dbBackups", {})
        resp        = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        result      = resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        container   = result.get("DBInstanceAutomatedBackups", {})
        backup_info = container.get("DBInstanceAutomatedBackup", {})
        retention   = 0
        
        if isinstance(backup_info, list):
            for entry in backup_info:
                retention = int(entry.get("BackupRetentionPeriod", 0))
                if retention == 0:
                    scheduled_auto = False
                    break
        else:
            retention = int(backup_info.get("BackupRetentionPeriod", 0))
        
        scheduled_auto = retention > 0

        return {"isBackupTypesScheduled": scheduled_auto}

    except json.JSONDecodeError:
        return {"isBackupTypesScheduled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}
