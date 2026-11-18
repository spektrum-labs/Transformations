"""
Transformation: backupJobFailures
Vendor: AWS (AWS Backup, read by the getBackupInventory method)
Category: Backups

The number of resources whose most recent AWS Backup job ended FAILED, ABORTED, EXPIRED or PARTIAL.
A later successful job clears the resource. Compare with isEquals 0. Not evaluated (None) when
backup:ListBackupJobs was refused, when the read was partial (an unreadable region, a truncated or
timed-out list) or when the inventory has no failed-job list.
"""

import json
from datetime import datetime, timedelta, timezone

SCHEMA_PREFIX = "aws-backup-inventory/"


def extract_input(input_data):
    data = input_data
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return None
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = data["data"]
    for attempt in range(4):
        if not isinstance(data, dict) or "schemaVersion" in data:
            break
        unwrapped = False
        for key in ["api_response", "apiResponse", "response", "result", "Output"]:
            if isinstance(data.get(key), dict):
                data = data[key]
                unwrapped = True
                break
        if not unwrapped:
            break
    return data


def inventory_of(data):
    """(inventory, reason it cannot be used)."""
    if not isinstance(data, dict):
        return None, "No AWS backup inventory in the response"
    if data.get("error") is True or str(data.get("status", "")).lower() == "error":
        return None, "The AWS backup inventory could not be read: " + str(data.get("message") or "error")
    if not str(data.get("schemaVersion", "")).startswith(SCHEMA_PREFIX):
        return None, "The response is not an AWS backup inventory"
    if not isinstance(data.get("resources"), list) or not isinstance(data.get("scope"), dict):
        return None, "The AWS backup inventory is incomplete"
    return data, None


def parse_time(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def denied(inventory, actions):
    """The actions in ``actions`` that the credentials were refused."""
    missing = []
    for entry in inventory["scope"].get("missingPermissions") or []:
        if isinstance(entry, dict) and entry.get("action") in actions:
            missing.append(entry.get("action"))
    return sorted(missing)


def label(resource):
    if not isinstance(resource, dict):
        return "unknown resource"
    return "%s %s (%s)" % (resource.get("type") or resource.get("service") or "resource",
                           resource.get("name") or resource.get("id") or resource.get("arn"),
                           resource.get("region") or "global")


def scope_warnings(inventory):
    scope = inventory["scope"]
    warnings = []
    missing = scope.get("missingPermissions") or []
    if missing:
        warnings.append("%d read action(s) were refused; resources they list are not counted: %s" % (
            len(missing), ", ".join(sorted(str(m.get("action")) for m in missing if isinstance(m, dict)))[:600]))
    unreachable = scope.get("regionsUnreachable") or {}
    if unreachable:
        warnings.append("Regions not readable: " + ", ".join(sorted(unreachable)))
    if scope.get("timedOut"):
        warnings.append("%d read(s) ran out of time" % len(scope.get("timedOut")))
    if scope.get("truncated"):
        warnings.append("%d list(s) were cut at a bound" % len(scope.get("truncated")))
    return warnings


def partial_read(inventory, any_missing=False):
    """Why the inventory is not the whole account, or None.

    A count or percentage taken from a partial read is not earned: a region nobody read, a list cut at a
    bound or a read that ran out of time can hide exactly the item the check looks for. Regions that
    are not opted in are not part of the account and do not count as a gap.
    """
    scope = inventory["scope"]
    gaps = []
    unreachable = scope.get("regionsUnreachable")
    if not isinstance(unreachable, dict):
        gaps.append("the inventory does not report unreadable regions")
    else:
        regions = []
        for region in unreachable:
            reason = str(unreachable.get(region)).replace("-", "").replace(" ", "").lower()
            if "optin" not in reason:
                regions.append(str(region))
        if regions:
            gaps.append("regions not readable: " + ", ".join(sorted(regions)))
    for key, what in (("timedOut", "read(s) ran out of time"), ("truncated", "list(s) were cut at a bound")):
        entries = scope.get(key)
        if not isinstance(entries, list):
            gaps.append("the inventory does not report " + key)
        elif entries:
            gaps.append("%d %s" % (len(entries), what))
    if any_missing:
        missing = scope.get("missingPermissions")
        if not isinstance(missing, list):
            gaps.append("the inventory does not report refused permissions")
        elif missing:
            gaps.append("%d read action(s) were refused: %s" % (len(missing), ", ".join(sorted(
                str(m.get("action")) for m in missing if isinstance(m, dict)))[:400]))
    if gaps:
        return "; ".join(gaps)
    return None


def create_response(criteria_key, value, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, errors=None, warnings=None, findings=None):
    measured = value is not None
    return {
        "transformedResponse": {criteria_key: value},
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else (errors or ["The response could not answer this check, so it was not evaluated."]),
            },
            "validation": {"status": "valid" if measured else "invalid", "errors": [], "warnings": warnings or []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "schemaVersion": "1.0",
                "transformationId": criteria_key,
                "vendor": "AWS",
                "category": "Backups",
                "input": "getBackupInventory",
            },
        },
    }


def not_evaluated(criteria_key, reason):
    return create_response(criteria_key, None, errors=[reason])


CRITERIA_KEY = "backupJobFailures"


def evaluate(inventory):
    refused = denied(inventory, ["backup:ListBackupJobs"])
    if refused:
        return not_evaluated(CRITERIA_KEY, "Backup jobs could not be read: refused backup:ListBackupJobs")
    gap = partial_read(inventory)
    if gap:
        return not_evaluated(CRITERIA_KEY, "Backup jobs could not be fully read: " + gap)
    attempts = inventory.get("failedLatestAttempts")
    if not isinstance(attempts, list):
        return not_evaluated(CRITERIA_KEY, "The inventory does not list failed backup jobs")
    failing = [f for f in attempts if isinstance(f, dict)]
    fail_reasons = []
    for item in failing[:20]:
        job = item.get("job") or {}
        fail_reasons.append("%s: latest job %s at %s%s" % (
            label(item), job.get("state"), job.get("createdAt"),
            (" - " + str(job.get("message"))) if job.get("message") else ""))
    states = (inventory.get("awsBackup") or {}).get("jobStates35d") or {}
    return create_response(CRITERIA_KEY, len(failing),
                           [] if failing else ["No resource's latest AWS Backup job failed"], fail_reasons, [],
                           {"failingResources": len(failing), "jobStates35d": states},
                           warnings=scope_warnings(inventory))


def transform(input):
    criteria = CRITERIA_KEY
    try:
        data = extract_input(input)
        inventory, reason = inventory_of(data)
        if inventory is None:
            return not_evaluated(criteria, reason)
        return evaluate(inventory)
    except Exception as e:
        return not_evaluated(criteria, "The transformation could not read the inventory")
