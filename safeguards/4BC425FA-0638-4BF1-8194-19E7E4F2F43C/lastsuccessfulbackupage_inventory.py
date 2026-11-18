"""
Transformation: lastSuccessfulBackupAge (inventory input)
Vendor: AWS (every service, read by the getBackupInventory method)
Category: Backups

Whole hours since the newest restorable point of the STALEST protected resource: the worst case, not
the best. The getBackups version of this check returned the age of the newest backup across all
resources, so one database with continuous backups held the value near 0 while other resources, or a
plan's runs, went stale. Resources with no backup at all are counted by backupCoveragePercentage.

Only resources with a restorable point are measured: one whose last backup aged out of retention drops
out, so the value can go down when that happens. The pass reason says how many were not measured, and
backupCoveragePercentage fails them.

Compare with lessThan (inclusive) the hours you allow. Not evaluated (None) when no resource has a
restorable point, or when the read was partial (refused actions, unreadable regions, truncated or
timed-out lists), because the stalest resource may be one nobody read.
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
    bound, a read that failed or ran out of time can hide exactly the item the check looks for. A region
    AWS refuses with OptInRequired is not part of the account and does not count as a gap.
    """
    scope = inventory["scope"]
    gaps = []
    unreachable = scope.get("regionsUnreachable")
    if not isinstance(unreachable, dict):
        gaps.append("the inventory does not report unreadable regions")
    else:
        regions = []
        for region in unreachable:
            # Only the exact AWS code for a region the account has not opted in to is exempt.
            if str(unreachable.get(region)).strip() != "OptInRequired":
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
    errors = scope.get("errors")
    if not isinstance(errors, list):
        gaps.append("the inventory does not report read errors")
    elif errors:
        gaps.append("%d read(s) failed: %s" % (len(errors), ", ".join(sorted(
            "%s %s" % (e.get("service"), e.get("operation")) for e in errors if isinstance(e, dict)))[:400]))
    if not gaps and scope.get("complete") is not True:
        gaps.append("the inventory is not marked complete")
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


CRITERIA_KEY = "lastSuccessfulBackupAge"


def evaluate(inventory):
    collected = parse_time(inventory.get("collectedAt"))
    if collected is None:
        return not_evaluated(CRITERIA_KEY, "The inventory has no collection time")
    gap = partial_read(inventory, any_missing=True)
    if gap:
        return not_evaluated(CRITERIA_KEY, "The stalest resource cannot be known from a partial read: " + gap)
    ages = []
    unmeasured = 0
    for res in inventory["resources"]:
        if not isinstance(res, dict) or res.get("backupCapable") is False:
            continue
        last = parse_time(res.get("lastGoodAt"))
        if last is not None:
            hours = int(max(0, (collected - last).total_seconds()) // 3600)
            ages.append((hours, res))
        else:
            unmeasured = unmeasured + 1
    if not ages:
        return not_evaluated(CRITERIA_KEY, "No resource has a restorable point to measure")
    ages.sort(key=lambda pair: pair[0])
    worst_hours, worst = ages[-1]
    stale = [pair for pair in ages if pair[0] > 26]
    findings = ["Stale: %s, %d hours" % (label(res), hours) for hours, res in stale[-15:]]
    return create_response(CRITERIA_KEY, worst_hours,
                           ["Stalest protected resource is %s, newest restorable point %d hours old%s"
                            % (label(worst), worst_hours,
                               ("; %d backup-capable resource(s) have no restorable point and are not measured "
                                "here (see backupCoveragePercentage)" % unmeasured) if unmeasured else "")],
                           [], [],
                           {"protectedResources": len(ages), "unmeasured": unmeasured, "stalest": label(worst),
                            "stalestLastGoodAt": worst.get("lastGoodAt"), "olderThan26h": len(stale)},
                           warnings=scope_warnings(inventory), findings=findings)


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
