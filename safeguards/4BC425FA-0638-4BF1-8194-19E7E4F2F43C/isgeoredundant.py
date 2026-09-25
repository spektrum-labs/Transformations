"""
Transformation: isGeoRedundant
Vendor: AWS (RDS automated backups)
Category: Backups

Evidence: the getBackups workflow, key dbBackups = RDS DescribeDBInstanceAutomatedBackups, whose
DBInstanceAutomatedBackupsReplications lists the cross-region copies of each automated backup.

Rule (fail closed): true when at least one automated backup is active and EVERY active one has a
replication whose ARN is in a different region from the backup's own Region. Retained backups of
deleted instances are counted but not judged.

Does not see: manual snapshot copies, AWS Backup cross-region copy rules, EBS/S3/EFS. A vendor
error or unreadable body is reported as a data-collection error (unevaluated), never as a pass.

This file previously held an Azure Recovery Services transform that read Azure-only fields.
"""

import json
from datetime import datetime, timezone

CRITERIA_KEY = "isGeoRedundant"


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


def arn_region(arn):
    parts = str(arn or "").split(":")
    return parts[3] if len(parts) > 3 else ""


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        backups, error = automated_backups(data)
        if error is not None:
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                api_errors=[error],
                fail_reasons=["Not measured: " + error]
            )

        active = [b for b in backups if str(b.get("Status", "")).lower() == "active"]
        findings = []
        failing = []
        for backup in active:
            name = str(backup.get("DBInstanceIdentifier") or "unknown")
            home = str(backup.get("Region") or arn_region(backup.get("DBInstanceArn")))
            replicas = as_list(dig(backup, ["DBInstanceAutomatedBackupsReplications", "DBInstanceAutomatedBackupsReplication"]))
            regions = [arn_region(r.get("DBInstanceAutomatedBackupsArn")) for r in replicas]
            remote = [r for r in regions if r and r != home]
            ok = len(remote) > 0
            if not ok:
                failing.append(name)
            findings.append({
                "metric": name,
                "value": ok,
                "reason": "home %s; replicated to %s" % (home or "unknown", ", ".join(remote) if remote else "no other region")
            })

        result_value = len(active) > 0 and len(failing) == 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("All %d active RDS automated backups are replicated to another region" % len(active))
        elif len(active) == 0:
            fail_reasons.append("No active RDS automated backup found (%d listed)" % len(backups))
            recommendations.append("Enable RDS automated backups and cross-region automated backup replication")
        else:
            fail_reasons.append("No cross-region replication for: %s" % ", ".join(failing))
            recommendations.append("Enable cross-Region automated backup replication on the listed instances")

        return create_response(
            result={CRITERIA_KEY: result_value, "activeAutomatedBackups": len(active)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={"automatedBackupsListed": len(backups), "active": len(active), "failing": len(failing)}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
