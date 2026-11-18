"""
Transformation: backupCoveragePercentage
Vendor: AWS (every service, read by the getBackupInventory method)
Category: Backups

The share of backup-capable resources in the account (every scanned region) that have a restorable
point no older than 7 days, from any mechanism: AWS Backup, service snapshots, automated or
point-in-time backups, or S3 versioning with replication. Integration-Service discovers the resources;
a resource with no backup at all counts against the share. Memcached clusters hold no data and are
not counted.

Compare with greaterThan (inclusive) the coverage you require, for example 100. Not evaluated (None)
when the account has no backup-capable resource or the inventory could not be read. Refused list
actions are named in the warnings; isBackupInventoryComplete fails on them.
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


CRITERIA_KEY = "backupCoveragePercentage"
MAX_AGE_DAYS = 7


def evaluate(inventory):
    collected = parse_time(inventory.get("collectedAt"))
    if collected is None:
        return not_evaluated(CRITERIA_KEY, "The inventory has no collection time")
    oldest_ok = collected - timedelta(days=MAX_AGE_DAYS)
    capable = [r for r in inventory["resources"] if isinstance(r, dict) and r.get("backupCapable") is not False]
    if not capable:
        return not_evaluated(CRITERIA_KEY, "No backup-capable resources were found in the scanned regions")
    covered = []
    uncovered = []
    for res in capable:
        last = parse_time(res.get("lastGoodAt"))
        if last is not None and last >= oldest_ok:
            covered.append(res)
        else:
            uncovered.append(res)
    pct = round(100.0 * len(covered) / len(capable), 2)
    by_type = {}
    for res in uncovered:
        key = res.get("type") or "unknown"
        by_type[key] = by_type.get(key, 0) + 1
    fail_reasons = []
    for res in uncovered[:20]:
        last = res.get("lastGoodAt")
        fail_reasons.append("%s: %s" % (label(res), ("newest restorable point " + str(last)) if last
                                        else "no backup of any kind"))
    if len(uncovered) > 20:
        fail_reasons.append("... and %d more" % (len(uncovered) - 20))
    pass_reasons = []
    if not uncovered:
        pass_reasons.append("All %d backup-capable resources have a restorable point from the last %d days"
                            % (len(capable), MAX_AGE_DAYS))
    return create_response(CRITERIA_KEY, pct, pass_reasons, fail_reasons,
                           ["Add the listed resources to an AWS Backup plan, or enable the service's own "
                            "automated backups for them"] if uncovered else [],
                           {"backupCapable": len(capable), "covered": len(covered), "uncovered": len(uncovered),
                            "uncoveredByType": by_type, "maxAgeDays": MAX_AGE_DAYS,
                            "regionsScanned": inventory["scope"].get("regionsScanned")},
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
