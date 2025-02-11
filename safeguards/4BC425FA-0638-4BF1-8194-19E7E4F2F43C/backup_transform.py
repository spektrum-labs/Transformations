def transform(input):
    """
    Evaluates the backup status of DB instances

    Parameters:
        input (dict): The JSON data containing DB Backup information.

    Returns:
        dict: A dictionary summarizing the DB backup information.
    """

    try:
        # Initialize counters
        total_db_instances = input.get("DescribeDBInstanceAutomatedBackupsResponse", {}).get("DescribeDBInstanceAutomatedBackupsResult",{}).get("DBInstanceAutomatedBackups",[])
        total_db_backups = len(total_db_instances)
        db_info = {
            "DBInstancesWithBackup": total_db_instances,
            "DBBackups": total_db_instances,
            "isBackupEnabled": False if total_db_backups == 0 else True
        }
        return db_info
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}
        