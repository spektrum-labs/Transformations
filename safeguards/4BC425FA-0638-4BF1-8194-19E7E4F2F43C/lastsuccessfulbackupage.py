"""
Transformation: lastSuccessfulBackupAge
Vendor: AWS (RDS and EBS)
Category: Backups

Evidence: the getBackups workflow:
  * dbBackups         RDS DescribeDBInstanceAutomatedBackups: RestoreWindow.LatestTime of each
                      active automated backup (the newest restorable point);
  * dbManualSnapshots RDS DescribeDBSnapshots: SnapshotCreateTime of each available snapshot;
  * volumeSnapshots   EC2 DescribeSnapshots: startTime of each completed snapshot.

Returns whole hours since the newest of those, as an integer, for a lessThan comparison.
Fail closed: when no backup time can be read the value is None, which no threshold accepts. When
every source is an error or unreadable it is also reported as a data-collection error
(unevaluated). A source that errored while another was readable is listed as a warning.

This file previously held an Azure Recovery Services transform that read Azure-only fields.
"""

import json
from datetime import datetime, timezone

CRITERIA_KEY = "lastSuccessfulBackupAge"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
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
                "transformationId": CRITERIA_KEY,
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


def vendor_error(data):
    """The vendor's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if not isinstance(data, dict):
        return None
    for key in ["error", "errors", "Error", "ErrorResponse", "__type", "errorType", "errorCode"]:
        value = data.get(key)
        if value:
            if isinstance(value, dict):
                inner = value.get("Error") if isinstance(value.get("Error"), dict) else value
                return str(inner.get("Message") or inner.get("message") or inner.get("Code") or value)
            return "%s: %s" % (value, data.get("Message") or data.get("message") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    return None


def as_list(value):
    """XML-derived bodies give a dict for one item, a list for several, and 'None' for zero."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def dig(data, path):
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def parse_time(value):
    if value is None or str(value).strip() in ("", "None"):
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def automated_backups(data):
    """(list of automated backups, error message or None) from the workflow or a bare response."""
    section = data.get("dbBackups") if isinstance(data, dict) and "dbBackups" in data else data
    error = vendor_error(section)
    if error is not None:
        return None, error
    response = section.get("DescribeDBInstanceAutomatedBackupsResponse") if isinstance(section, dict) else None
    if not isinstance(response, dict):
        return None, "Response has no DescribeDBInstanceAutomatedBackupsResponse; RDS automated backups were not read"
    items = dig(response, ["DescribeDBInstanceAutomatedBackupsResult", "DBInstanceAutomatedBackups", "DBInstanceAutomatedBackup"])
    return as_list(items), None


def snapshot_times(data):
    """(list of (source, identifier, time), list of source errors)."""
    times = []
    errors = []
    if not isinstance(data, dict):
        return times, ["Response is not an object"]

    backups, error = automated_backups(data)
    if error is not None:
        errors.append("dbBackups: " + error)
    else:
        for b in backups:
            if str(b.get("Status", "")).lower() == "active":
                t = parse_time(dig(b, ["RestoreWindow", "LatestTime"]))
                if t is not None:
                    times.append(("RDS automated backup", str(b.get("DBInstanceIdentifier")), t))

    if "dbManualSnapshots" in data:
        section = data.get("dbManualSnapshots")
        error = vendor_error(section)
        response = section.get("DescribeDBSnapshotsResponse") if isinstance(section, dict) else None
        if error is None and not isinstance(response, dict):
            error = "no DescribeDBSnapshotsResponse"
        if error is not None:
            errors.append("dbManualSnapshots: " + error)
        else:
            for s in as_list(dig(response, ["DescribeDBSnapshotsResult", "DBSnapshots", "DBSnapshot"])):
                if str(s.get("Status", "")).lower() == "available":
                    t = parse_time(s.get("SnapshotCreateTime"))
                    if t is not None:
                        times.append(("RDS snapshot", str(s.get("DBSnapshotIdentifier")), t))

    if "volumeSnapshots" in data:
        section = data.get("volumeSnapshots")
        error = vendor_error(section)
        response = section.get("DescribeSnapshotsResponse") if isinstance(section, dict) else None
        if error is None and not isinstance(response, dict):
            error = "no DescribeSnapshotsResponse"
        if error is not None:
            errors.append("volumeSnapshots: " + error)
        else:
            for s in as_list(dig(response, ["snapshotSet", "item"])):
                if str(s.get("status", "")).lower() == "completed":
                    t = parse_time(s.get("startTime"))
                    if t is not None:
                        times.append(("EBS snapshot", str(s.get("snapshotId")), t))

    return times, errors


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        error = vendor_error(data)
        if error is not None:
            return create_response(
                result={CRITERIA_KEY: None},
                validation=validation,
                api_errors=[error],
                fail_reasons=["Not measured: " + error]
            )

        times, errors = snapshot_times(data)
        sources = [k for k in ["dbBackups", "dbManualSnapshots", "volumeSnapshots"] if isinstance(data, dict) and k in data]
        if len(times) == 0 and len(errors) >= max(len(sources), 1):
            return create_response(
                result={CRITERIA_KEY: None},
                validation=validation,
                api_errors=errors,
                fail_reasons=["Not measured: no backup source could be read"]
            )
        if errors:
            validation = {"status": "unknown", "errors": [], "warnings": errors}

        if len(times) == 0:
            return create_response(
                result={CRITERIA_KEY: None},
                validation=validation,
                fail_reasons=["No successful backup found in RDS automated backups, RDS snapshots or EBS snapshots"],
                recommendations=["Enable RDS automated backups or scheduled snapshots"],
                input_summary={"backupTimesFound": 0}
            )

        now = datetime.now(timezone.utc)
        newest = times[0]
        for entry in times:
            if entry[2] > newest[2]:
                newest = entry
        hours = int((now - newest[2]).total_seconds() // 3600)
        if hours < 0:
            hours = 0

        return create_response(
            result={CRITERIA_KEY: hours, "newestBackupAt": newest[2].isoformat(), "newestBackupSource": newest[0]},
            validation=validation,
            pass_reasons=["Newest successful backup is %d hours old (%s %s)" % (hours, newest[0], newest[1])],
            input_summary={"backupTimesFound": len(times)}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
