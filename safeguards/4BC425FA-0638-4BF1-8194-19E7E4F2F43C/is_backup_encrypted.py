"""
Transformation: isBackupEncrypted
Vendor: AWS
Category: Backups / Security

Checks that all backups (RDS automated, RDS manual, EBS) are encrypted at rest.
"""

import json
from datetime import datetime

#: The criterion this file answers; a None value is reported as not measured.
CRITERIA_KEY = "isBackupEncrypted"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    # Not measured is read off the criterion's value, so every path that leaves it None -- the
    # except branch included -- reaches Token-Service as not evaluated rather than as a gap.
    measured = result.get(CRITERIA_KEY) is not None
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else (api_errors or fail_reasons or transformation_errors
                                               or ["The response could not answer this check, so it was not evaluated."])
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupEncrypted",
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


#: The getBackups workflow sections this check reads, each with the describe response it must carry.
SECTIONS = (("dbBackups", "DescribeDBInstanceAutomatedBackupsResponse"),
            ("dbManualSnapshots", "DescribeDBSnapshotsResponse"),
            ("volumeSnapshots", "DescribeSnapshotsResponse"))


def unread_sections(data, sections):
    """The workflow sections that did not come back as a describe response: absent, null or an error
    envelope. A reading that lacks one of them has not looked at that kind of backup."""
    if not isinstance(data, dict):
        return [name for name, response in sections]
    return [name for name, response in sections
            if not (isinstance(data.get(name), dict) and isinstance(data[name].get(response), dict))]

def transform(input):
    auto_enc = True
    man_enc = True
    ebs_enc = True

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isBackupEncrypted": None, "isAutoBackupEncrypted": None, "isManualBackupEncrypted": None, "isEbsBackupEncrypted": None},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # A SECTION THAT IS PRESENT BUT NULL, OR PRESENT BUT NOT A DICT, MUST NOT RAISE.
        # data.get(name, {}) returns None for "volumeSnapshots": null, because the key IS
        # present, and the first volume_snapshots.get(...) below then raised AttributeError
        # into the except branch -- turning an account with a readable unencrypted RDS
        # backup into Not evaluated instead of the red it had earned. Coerce here so such a
        # section flows to unread_sections, which already classifies it as unread.
        db_backups = data.get("dbBackups")
        db_manual_snapshots = data.get("dbManualSnapshots")
        volume_snapshots = data.get("volumeSnapshots")
        db_backups = db_backups if isinstance(db_backups, dict) else {}
        db_manual_snapshots = db_manual_snapshots if isinstance(db_manual_snapshots, dict) else {}
        volume_snapshots = volume_snapshots if isinstance(volume_snapshots, dict) else {}

        # A BODY CARRYING NONE OF THE THREE SECTIONS WAS SCANNED ZERO TIMES. Unlike a null
        # body -- which raises and is handled below -- {} and an error envelope parse
        # cleanly, so every snapshot list came back empty, no flag was ever lowered, and
        # all four criteria reported ENCRYPTED. "No unencrypted snapshot was found" is only
        # a finding when snapshots were looked at; here nothing was.
        error_keys = ("error", "errors", "errorMessage", "errorType", "fault")
        sections_present = any(
            isinstance(data.get(k), (dict, list)) and data.get(k)
            for k in ("dbBackups", "dbManualSnapshots", "volumeSnapshots")
        )
        if not data or any(data.get(k) for k in error_keys) or not sections_present:
            return create_response(
                result={"isBackupEncrypted": None, "isAutoBackupEncrypted": None,
                        "isManualBackupEncrypted": None, "isEbsBackupEncrypted": None},
                validation=validation,
                fail_reasons=[
                    "The response carried none of dbBackups, dbManualSnapshots or "
                    "volumeSnapshots (empty body, an error response, or an unrecognised "
                    "shape), so no snapshot was scanned and encryption could not be "
                    "verified. This is the absence of a reading, not a finding that "
                    "backups are unencrypted."
                ],
                recommendations=[
                    "Confirm the AWS credential is valid and that the describe calls "
                    "returned 2xx bodies before reading this criterion."
                ],
                input_summary={"snapshotSectionsPresent": False}
            )

        def listify(container, key=None):
            if key and isinstance(container, dict) and key in container:
                entry = container[key]
                return entry if isinstance(entry, list) else [entry]
            if isinstance(container, list):
                return container
            return []

        # Automated backups
        auto_resp = db_backups.get("DescribeDBInstanceAutomatedBackupsResponse", {})
        auto_res = auto_resp.get("DescribeDBInstanceAutomatedBackupsResult", {})
        auto_group = auto_res.get("DBInstanceAutomatedBackups", {})
        auto_list = listify(auto_group, "DBInstanceAutomatedBackup")

        # Manual snapshots
        man_resp = db_manual_snapshots.get("DescribeDBSnapshotsResponse", {})
        man_res = man_resp.get("DescribeDBSnapshotsResult", {})
        man_group = man_res.get("DBSnapshots", {})
        if isinstance(man_group, dict):
            man_group = man_group.get("DBSnapshot", [])
        manual_list = man_group if isinstance(man_group, list) else [man_group] if isinstance(man_group, dict) else []

        # EBS snapshots
        ebs_resp = volume_snapshots.get("DescribeSnapshotsResponse", {})
        ebs_group = ebs_resp.get("snapshotSet", {})
        if isinstance(ebs_group, dict):
            ebs_group = ebs_group.get("item", [])
        ebs_list = ebs_group if isinstance(ebs_group, list) else [ebs_group] if isinstance(ebs_group, dict) else []

        # Check encryption flags
        unencrypted_auto = []
        for item in auto_list:
            if str(item.get("Encrypted", "")).lower() != "true":
                auto_enc = False
                unencrypted_auto.append(item.get("DBInstanceIdentifier", "unknown"))

        unencrypted_manual = []
        for item in manual_list:
            if str(item.get("Encrypted", "")).lower() != "true":
                man_enc = False
                unencrypted_manual.append(item.get("DBSnapshotIdentifier", "unknown"))

        unencrypted_ebs = []
        for item in ebs_list:
            if str(item.get("encrypted", "")).lower() != "true":
                ebs_enc = False
                unencrypted_ebs.append(item.get("snapshotId", "unknown"))

        all_enc = auto_enc and man_enc and ebs_enc

        # An unencrypted snapshot found in what was read is a finding; "all encrypted" only counts when every
        # section was read, since the unread one may hold the unencrypted snapshot.
        unread = unread_sections(data, SECTIONS)
        if unread and all_enc:
            return create_response(
                result={"isBackupEncrypted": None, "isAutoBackupEncrypted": None,
                        "isManualBackupEncrypted": None, "isEbsBackupEncrypted": None},
                validation=validation,
                api_errors=[", ".join(unread) + " did not return a describe response, so those backups were not read"],
                fail_reasons=["Not measured: " + ", ".join(unread) + " did not return a describe response, so those backups were not read"],
                recommendations=["Confirm the AWS credential can call the describe APIs and that each returned a 2xx body."]
            )

        additional_findings = []

        # Primary criteria: isBackupEncrypted (all backups encrypted)
        if all_enc:
            total_backups = len(auto_list) + len(manual_list) + len(ebs_list)
            if total_backups > 0:
                pass_reasons.append(f"All {total_backups} backups are encrypted")
            else:
                pass_reasons.append("No backups found to evaluate encryption")
        else:
            unencrypted_total = len(unencrypted_auto) + len(unencrypted_manual) + len(unencrypted_ebs)
            fail_reasons.append(f"{unencrypted_total} backups are not encrypted")

        # Additional finding: isAutoBackupEncrypted
        if len(auto_list) > 0:
            if auto_enc:
                additional_findings.append({
                    "metric": "isAutoBackupEncrypted",
                    "status": "pass",
                    "reason": f"All {len(auto_list)} automated RDS backups are encrypted"
                })
            else:
                additional_findings.append({
                    "metric": "isAutoBackupEncrypted",
                    "status": "fail",
                    "reason": f"{len(unencrypted_auto)} automated RDS backups not encrypted",
                    "recommendation": "Enable encryption for RDS automated backups"
                })

        # Additional finding: isManualBackupEncrypted
        if len(manual_list) > 0:
            if man_enc:
                additional_findings.append({
                    "metric": "isManualBackupEncrypted",
                    "status": "pass",
                    "reason": f"All {len(manual_list)} manual RDS snapshots are encrypted"
                })
            else:
                additional_findings.append({
                    "metric": "isManualBackupEncrypted",
                    "status": "fail",
                    "reason": f"{len(unencrypted_manual)} manual RDS snapshots not encrypted",
                    "recommendation": "Enable encryption for RDS manual snapshots"
                })

        # Additional finding: isEbsBackupEncrypted
        if len(ebs_list) > 0:
            if ebs_enc:
                additional_findings.append({
                    "metric": "isEbsBackupEncrypted",
                    "status": "pass",
                    "reason": f"All {len(ebs_list)} EBS snapshots are encrypted"
                })
            else:
                additional_findings.append({
                    "metric": "isEbsBackupEncrypted",
                    "status": "fail",
                    "reason": f"{len(unencrypted_ebs)} EBS snapshots not encrypted",
                    "recommendation": "Enable encryption for EBS snapshots"
                })

        # EACH SUB-CRITERION ANSWERS ONLY FOR ITS OWN SECTION. auto_enc, man_enc and ebs_enc
        # are initialised True and are lowered only by finding an unencrypted item, so a
        # section that was never read leaves its flag True -- True from missing data, the
        # same defect the except branch below warns about. Reaching here with anything in
        # `unread` means the guard above did not fire, i.e. SOMETHING read was unencrypted:
        # the top-level False is a real finding (one unencrypted item settles the fail
        # whatever else went unread), but a sub-key whose section was never read has no
        # answer. `measured` is keyed on isBackupEncrypted alone, so that False stays graded.
        return create_response(
            result={
                "isBackupEncrypted": all_enc,
                "isAutoBackupEncrypted": None if "dbBackups" in unread else auto_enc,
                "isManualBackupEncrypted": None if "dbManualSnapshots" in unread else man_enc,
                "isEbsBackupEncrypted": None if "volumeSnapshots" in unread else ebs_enc
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "autoBackupCount": len(auto_list),
                "manualSnapshotCount": len(manual_list),
                "ebsSnapshotCount": len(ebs_list),
                "unencryptedAutoCount": len(unencrypted_auto),
                "unencryptedManualCount": len(unencrypted_manual),
                "unencryptedEbsCount": len(unencrypted_ebs)
            }
        )

    except Exception as e:
        # THE THREE SUB-CRITERIA MUST NOT SURVIVE THE EXCEPTION AS True. auto_enc, man_enc
        # and ebs_enc are initialised True ABOVE the try and are only ever lowered by
        # finding an unencrypted snapshot. An exception raised before that scan -- which is
        # what a null or non-dict body produces, at the first data.get() -- left all three
        # at their initial value, so this handler reported isBackupEncrypted false while
        # simultaneously reporting isAutoBackupEncrypted, isManualBackupEncrypted and
        # isEbsBackupEncrypted TRUE. Measured 2026-09-21: transform(None) asserted all
        # three. Nothing was scanned, so none of the three has an answer.
        return create_response(
            result={"isBackupEncrypted": None, "isAutoBackupEncrypted": None,
                    "isManualBackupEncrypted": None, "isEbsBackupEncrypted": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}",
                          "No snapshot was scanned, so encryption could not be verified "
                          "for automated backups, manual snapshots or EBS snapshots."]
        )
