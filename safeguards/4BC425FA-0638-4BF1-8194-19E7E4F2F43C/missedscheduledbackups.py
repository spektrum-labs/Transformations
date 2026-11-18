"""
Transformation: missedScheduledBackups
Vendor: AWS (AWS Backup, read by the getBackupInventory method)
Category: Backups

Counts the scheduled backup runs in the last 48 hours that did not happen: every AWS Backup plan rule's
schedule, evaluated by Integration-Service against the job history for every resource the plan covers.
A run that never started (missed) and a run whose job failed both count. A restorable point from some
other mechanism does not excuse a missed run: this check is about the plan doing what it says.

Compare with isEquals 0. Not evaluated (None) when the job or plan reads were refused, when any region
was unreadable or any list was truncated or timed out, when a plan rule could not be checked against the
job history, or when the inventory has no missed-run list, because a zero from unread history would be a
pass nobody earned. A missed or failed run with no readable time still counts.
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


CRITERIA_KEY = "missedScheduledBackups"
WINDOW_HOURS = 48
REQUIRED = ["backup:ListBackupJobs", "backup:ListBackupPlans", "backup:GetBackupPlan"]


def evaluate(inventory):
    refused = denied(inventory, REQUIRED)
    if refused:
        return not_evaluated(CRITERIA_KEY, "Backup schedules could not be checked: refused " + ", ".join(refused))
    gap = partial_read(inventory)
    if gap:
        return not_evaluated(CRITERIA_KEY, "Backup schedules could not be fully checked: " + gap)
    runs = inventory.get("missedRuns")
    if not isinstance(runs, list):
        return not_evaluated(CRITERIA_KEY, "The inventory does not list missed or failed runs")
    backup = inventory.get("awsBackup")
    if not isinstance(backup, dict) or not isinstance(backup.get("plans"), list):
        return not_evaluated(CRITERIA_KEY, "The inventory does not list AWS Backup plans")
    collected = parse_time(inventory.get("collectedAt"))
    if collected is None:
        return not_evaluated(CRITERIA_KEY, "The inventory has no collection time")
    since = collected - timedelta(hours=WINDOW_HOURS)
    names = {}
    for res in inventory["resources"]:
        if isinstance(res, dict):
            names[res.get("arn")] = res
    recent = []
    for run in runs:
        if not isinstance(run, dict) or run.get("status") not in ("missed", "failed"):
            continue
        expected = parse_time(run.get("expectedAt"))
        # A missed or failed run with no readable time is counted: dropping it would turn a miss into a pass.
        if expected is None or expected >= since:
            recent.append(run)
    plans = [p for p in backup["plans"] if isinstance(p, dict)]
    rules = 0
    unevaluated = []
    for plan in plans:
        for rule in plan.get("rules") or []:
            rules = rules + 1
            if rule.get("evaluated") is False:
                unevaluated.append("%s / %s: %s" % (plan.get("name"), rule.get("name"), rule.get("reason")))
    if unevaluated:
        return not_evaluated(CRITERIA_KEY, "%d plan rule(s) could not be checked against the job history: %s"
                             % (len(unevaluated), "; ".join(unevaluated)[:600]))
    fail_reasons = []
    for run in recent[:15]:
        fail_reasons.append("%s: %s run of plan %s rule %s expected at %s%s" % (
            label(names.get(run.get("arn")) or run), run.get("status"), run.get("planName"), run.get("ruleName"),
            run.get("expectedAt"), (" (job " + str(run.get("jobState")) + ")") if run.get("jobState") else ""))
    if len(recent) > 15:
        fail_reasons.append("... and %d more" % (len(recent) - 15))
    pass_reasons = []
    if not recent:
        pass_reasons.append("Every scheduled AWS Backup run in the last %d hours started (%d plan(s), %d rule(s))"
                            % (WINDOW_HOURS, len(plans), rules))
    findings = []
    if not plans:
        findings.append("No AWS Backup plans exist, so no scheduled runs were expected")
    return create_response(CRITERIA_KEY, len(recent), pass_reasons, fail_reasons,
                           ["Open AWS Backup > Jobs for each listed run: a run that never started is usually a "
                            "plan edited during its start window, a deleted or renamed resource, or a role that "
                            "lost access"] if recent else [],
                           {"plans": len(plans), "rules": rules, "windowHours": WINDOW_HOURS,
                            "missedOrFailed": len(recent)},
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
