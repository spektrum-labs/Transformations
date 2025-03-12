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

        response = input.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        result = response.get("DescribeDBInstanceAutomatedBackupsResult", {})
        db_instances = result.get("DBInstanceAutomatedBackups", [])

        # Count total backups
        if isinstance(db_instances, dict):
            db_instances = [db_instances]
            
        total_db_backups = len(db_instances)

        # Construct the output
        db_info = {
            "isBackupEnabled": total_db_backups > 0
        }

        return db_info

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON format."}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}
