# isbackupenabled.py

import json

def transform(input):
    """
    Evaluates whether any backups exist across RDS automated, RDS manual, or EBS snapshots.
    Returns: {"isBackupEnabled": bool}
    """
    try:
        # Parse JSON if needed
        data = _parse_input(input)

        # Drill down past response/result wrappers if present
        data = data.get("response", data).get("result", data)

        # Extract each backup category
        dbBackups          = data.get("dbBackups", {})
        dbManualSnapshots  = data.get("dbManualSnapshots", {})
        volumeSnapshots    = data.get("volumeSnapshots", {})

        # Automated RDS
        auto_resp   = dbBackups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_res    = auto_resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_group  = auto_res.get("DBInstanceAutomatedBackups", [])
        if isinstance(auto_group, dict):
            auto_group = [auto_group]
        automated   = auto_group

        # Manual RDS
        man_resp    = dbManualSnapshots.get("DescribeDBSnapshotsResponse", {})
        man_res     = man_resp.get("DescribeDBSnapshotsResult", {})
        man_group   = man_res.get("DBSnapshots", {}).get("DBSnapshot", [])
        if isinstance(man_group, dict):
            man_group = [man_group]
        manual      = man_group

        # EBS snapshots
        ebs_resp    = volumeSnapshots.get("DescribeSnapshotsResponse", {})
        ebs_group   = ebs_resp.get("snapshotSet", {}).get("item", [])
        if isinstance(ebs_group, dict):
            ebs_group = [ebs_group]
        ebs         = ebs_group

        return {"isBackupEnabled": bool(automated or manual or ebs)}

    except json.JSONDecodeError:
        return {"isBackupEnabled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def _parse_input(input):
    if isinstance(input, str):
        return json.loads(input)
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")
