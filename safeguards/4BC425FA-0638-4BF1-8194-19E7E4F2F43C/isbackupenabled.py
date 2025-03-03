import json

def transform(input):
    """
    Evaluates the backup status of DB instances.

    Parameters:
        input (str | dict): The JSON data containing DB Backup information. 
                            If a string is provided, it will be parsed.

    Returns:
        dict: A dictionary summarizing the DB backup information.
    """

    try:
        # Ensure input is a dictionary by parsing if necessary
        if isinstance(input, str):
            input = json.loads(input)  # Convert JSON string to dictionary
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))  # Decode bytes then parse JSON
        
        if not isinstance(input, dict):
            raise ValueError("JSON input must be an object (dictionary).")

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

        #Check for Volume Snapshots
        response = volumeSnapshots.get("DescribeSnapshotsResponse", {})
        result = response.get("DescribeSnapshotsResult", {})
        volume_snapshots = result.get("Snapshots", {})

        # Count total volume backups
        if isinstance(volume_snapshots, dict):
            volume_snapshots = [volume_snapshots]
            
        volume_backups = len(volume_snapshots)
        
        # Construct the output
        backup_info = {
            "automatedBackups": automated_backups,
            "manualBackups": manual_backups,
            "volumeBackups": volume_backups,
            "isBackupEnabled": total_db_backups > 0 or volume_backups > 0
        }

        return backup_info

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON format."}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}