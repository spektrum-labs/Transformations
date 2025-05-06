# is_backup_logging_enabled.py

import json
    
def transform(input):
    """
    Checks whether logging is enabled and sending to SIEM if possible.
    Returns: {"isBackupLoggingEnabled": bool}
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
    
        # Ensure input is a dictionary by parsing if necessary
        input = _parse_input(input)

        # Extract response safely
        input = input.get("response",input)
        input = input.get("result",input)

        if 'dbBackups' in input:
            dbBackups = input.get("dbBackups",input)
        
        if 'dbManualSnapshots' in input:
            dbManualSnapshots = input.get("dbManualSnapshots",input)
        
        if 'volumeSnapshots' in input:
            volumeSnapshots = input.get("volumeSnapshots",input)
            
        #Check for Automated DB Backups
        response = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        result = response.get("DescribeDBInstanceAutomatedBackupsResult", {})
        automated_backups = result.get("DBInstanceAutomatedBackups", [])

        # Count total backups
        if isinstance(automated_backups, dict):
            automated_backups = [automated_backups]
            
        total_db_backups = len(automated_backups)

        #Check for Manual DB Backups
        response = dbManualSnapshots.get("DescribeDBSnapshotsResponse", {})
        result = response.get("DescribeDBSnapshotsResult", {})
        manual_backups = result.get("DBSnapshots", {})
        manual_backups = manual_backups.get("DBSnapshot", [])
        
        # Count total backups
        if isinstance(manual_backups, dict):
            manual_backups = [manual_backups]
            
        total_db_backups += len(manual_backups)

        # No restore/test records in this payload → always False
        logging_enabled = True if total_db_backups > 0 else False
        
        return {"isBackupLoggingEnabled": logging_enabled}

    except json.JSONDecodeError:
        return {"isBackupLoggingEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}
