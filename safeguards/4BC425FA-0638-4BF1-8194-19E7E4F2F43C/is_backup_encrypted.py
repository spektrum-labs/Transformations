# is_backup_encrypted.py

import json

def transform(input):
    """
    Checks that all backups (RDS automated, RDS manual, EBS) are encrypted at rest.
    Returns: {"isBackupEncrypted": bool}
    """
    all_enc = True
    auto_enc=True
    man_enc=True
    ebs_enc=True
    try:
        def _parse_input(input):
            if isinstance(input, str):
                return json.loads(input)
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        data              = _parse_input(input).get("response", {}).get("result", _parse_input(input))
        dbBackups         = data.get("dbBackups", {})
        dbManualSnapshots = data.get("dbManualSnapshots", {})
        volumeSnapshots   = data.get("volumeSnapshots", {})

        # Helper to collect lists
        def _listify(container, key=None):
            if key and isinstance(container, dict) and key in container:
                entry = container[key]
                return entry if isinstance(entry, list) else [entry]
            if isinstance(container, list):
                return container
            return []

        # Automated
        auto_resp  = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_res   = auto_resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_group = auto_res.get("DBInstanceAutomatedBackups", {})
        auto_list  = _listify(auto_group, "DBInstanceAutomatedBackup")

        # Manual
        man_resp   = dbManualSnapshots.get("DescribeDBSnapshotsResponse", {})
        man_res    = man_resp.get("DescribeDBSnapshotsResult", {})
        man_group  = man_res.get("DBSnapshots", {}).get("DBSnapshot", [])
        manual_list= man_group if isinstance(man_group, list) else [man_group] if isinstance(man_group, dict) else []

        # EBS
        ebs_resp   = volumeSnapshots.get("DescribeSnapshotsResponse", {})
        ebs_group  = ebs_resp.get("snapshotSet", {}).get("item", [])
        ebs_list   = ebs_group if isinstance(ebs_group, list) else [ebs_group] if isinstance(ebs_group, dict) else []

        # Check encryption flags
        for item in auto_list:
            if str(item.get("Encrypted", "")).lower() != "true":
                auto_enc = False
        for item in manual_list:
            if str(item.get("Encrypted", "")).lower() != "true":
                man_enc = False
        for item in ebs_list:
            if str(item.get("encrypted", "")).lower() != "true":
                ebs_enc = False

        all_enc = auto_enc and man_enc and ebs_enc
        
        return {"isBackupEncrypted": all_enc, "isAutoBackupEncrypted": auto_enc, "isManualBackupEncrypted": man_enc, "isEbsBackupEncrypted": ebs_enc}

    except json.JSONDecodeError:
        return {"isBackupEncrypted": False, "isAutoBackupEncrypted": auto_enc, "isManualBackupEncrypted": man_enc, "isEbsBackupEncrypted": ebs_enc, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEncrypted": False, "isAutoBackupEncrypted": auto_enc, "isManualBackupEncrypted": man_enc, "isEbsBackupEncrypted": ebs_enc, "error": str(e)}
