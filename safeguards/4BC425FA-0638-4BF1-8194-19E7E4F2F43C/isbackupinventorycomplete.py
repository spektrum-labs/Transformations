"""
Transformation: isBackupInventoryComplete
Vendor: AWS (read by the getBackupInventory method)
Category: Backups

True only when the backup inventory saw the whole account: every enabled region answered, every read
action was allowed, no list was cut short and nothing ran out of time. When False, the fail reasons name
what is missing (usually IAM actions to add to the read-only policy in the setup instructions), because every other
backup check can only speak for what was seen.

Unlike the counting checks, this one also fails on a region AWS refuses with OptInRequired: the
account lists it as enabled, so the inventory did not see all of it.
"""

import json
from datetime import datetime, timedelta, timezone

SCHEMA_PREFIX = "aws-backup-inventory/"


def extract_input(input_data):
    data = input_data
    if isinstance(data, bytes):
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


CRITERIA_KEY = "isBackupInventoryComplete"


def evaluate(inventory):
    scope = inventory["scope"]
    reasons = []
    for entry in scope.get("missingPermissions") or []:
        if isinstance(entry, dict):
            reasons.append("Refused %s in %s" % (entry.get("action"), ", ".join(entry.get("regions") or [])))
    for region, why in sorted((scope.get("regionsUnreachable") or {}).items()):
        reasons.append("Region %s refused the credentials (%s)" % (region, why))
    for item in scope.get("timedOut") or []:
        reasons.append("Ran out of time reading %s in %s" % (item.get("collector"), item.get("region")))
    for item in scope.get("truncated") or []:
        reasons.append("Cut at %s items: %s %s" % (item.get("kept"), item.get("service"), item.get("what")))
    for item in (scope.get("errors") or [])[:10]:
        reasons.append("Error %s from %s %s in %s" % (item.get("code"), item.get("service"), item.get("operation"),
                                                       item.get("region")))
    complete = scope.get("complete") is True and not reasons
    return create_response(CRITERIA_KEY, complete,
                           ["Read %d region(s) with every action allowed" % len(scope.get("regionsScanned") or [])]
                           if complete else [], reasons[:40],
                           [] if complete else ["Attach the read-only backup policy (all actions listed "
                                                "in the setup instructions) to the connected role or user"],
                           {"regionsScanned": scope.get("regionsScanned"),
                            "missingPermissions": len(scope.get("missingPermissions") or [])})


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
