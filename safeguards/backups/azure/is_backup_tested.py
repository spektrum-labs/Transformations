"""
Transformation: isBackupTested
Vendor: Azure Recovery Services
Category: Backup / Data Protection

Checks whether a backup restore has actually been exercised and succeeded
recently, which is what demonstrates recoverability. A backup job reporting
"Completed" only proves data was written, not that it can be read back.

Data source: getRestoreJobStatus - the Recovery Services ARM API
(backupJobs?$filter=operation eq 'Restore'), iterated per vault from
listVaults.

Note: this previously read getRestoreJobs, an Azure Resource Graph query.
ARG only retains backup job history for ~15 days, so any restore test older
than that was invisible and the criterion reported "no restore operations
found" for customers who had in fact tested. The ARM endpoint returns the
full restore history with no date bound.

Pass condition: at least one restore job with a terminal successful status
(Completed or CompletedWithWarnings) that finished within RECENCY_DAYS.
Failed restores are counted as evidence against, not for - a restore that
errored did not demonstrate recoverability.
"""

import json
from datetime import datetime, timedelta

SUCCESS_STATUSES = ["Completed", "CompletedWithWarnings"]
RECENCY_DAYS = 365
MAX_WALK_DEPTH = 6


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
                "transformationId": "isBackupTested",
                "vendor": "Azure",
                "category": "Backup"
            }
        }
    }


def parse_azure_time(value):
    """Azure returns 7-digit fractional seconds and a Z suffix, which the
    stdlib ISO parser rejects.

    Built by hand from the fixed-width YYYY-MM-DDTHH:MM:SS prefix rather than
    with datetime.strptime: strptime lazily imports _strptime, which the
    RestrictedPython sandbox blocks. That import error is swallowed by the
    caller's guard, every timestamp parses as None, and successful restores get
    miscounted as out-of-window. It passes unsandboxed and fails in prod.
    """
    if not isinstance(value, str) or len(value) < 19:
        return None
    try:
        return datetime(
            int(value[0:4]), int(value[5:7]), int(value[8:10]),
            int(value[11:13]), int(value[14:16]), int(value[17:19])
        )
    except Exception:
        return None


def collect_restore_jobs(node, found, depth):
    """Walk the per-vault iterate payload and collect restore job objects.

    The payload carries the same jobs more than once (once under restoreJobs
    from the returnSpec, again under apiResponse.value from rawResponse), so
    jobs are keyed by id to avoid double counting.
    """
    if depth > MAX_WALK_DEPTH:
        return
    if isinstance(node, list):
        for item in node:
            collect_restore_jobs(item, found, depth + 1)
    elif isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict) and props.get("operation") == "Restore":
            key = node.get("id")
            if not key:
                key = "job-" + str(len(found))
            found[key] = node
            return
        for key in ["restoreJobResults", "restoreJobs", "value", "apiResponse", "data"]:
            if key in node:
                collect_restore_jobs(node[key], found, depth + 1)


def rows_from_arg_table(data):
    """Fallback for the legacy Resource Graph payload, so this transform is
    safe to ship before the definition is repointed to the ARM endpoint."""
    jobs = []
    if not isinstance(data, dict):
        return jobs
    inner = data.get("data", data)
    if not isinstance(inner, dict):
        return jobs
    columns = inner.get("columns")
    rows = inner.get("rows")
    if not isinstance(columns, list) or not isinstance(rows, list):
        return jobs
    names = []
    for col in columns:
        if isinstance(col, dict):
            names.append(col.get("name"))
        else:
            names.append(None)
    for row in rows:
        if not isinstance(row, list):
            continue
        record = {}
        for index in range(min(len(names), len(row))):
            if names[index]:
                record[names[index]] = row[index]
        jobs.append({
            "id": record.get("name"),
            "properties": {
                "operation": "Restore",
                "status": record.get("jobStatus"),
                "endTime": record.get("endTime"),
                "startTime": record.get("startTime"),
                "entityFriendlyName": record.get("itemName")
            }
        })
    return jobs


def describe(job_props):
    name = job_props.get("entityFriendlyName")
    if not name:
        name = "unnamed item"
    stamp = job_props.get("endTime")
    if not stamp:
        stamp = job_props.get("startTime")
    if isinstance(stamp, str) and len(stamp) >= 10:
        stamp = stamp[0:10]
    else:
        stamp = "unknown date"
    return str(name) + " (" + str(job_props.get("status")) + ") on " + stamp


def transform(input):
    criteriaKey = "isBackupTested"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        found = {}
        collect_restore_jobs(data, found, 0)
        jobs = list(found.values())
        if not jobs:
            jobs = rows_from_arg_table(data)

        now = datetime.utcnow()
        cutoff = now - timedelta(days=RECENCY_DAYS)

        qualifying = 0
        stale = 0
        failed = 0
        newest = None
        newest_label = ""
        findings = []

        for job in jobs:
            props = job.get("properties", {})
            if not isinstance(props, dict):
                continue
            status = props.get("status")
            when = parse_azure_time(props.get("endTime"))
            if when is None:
                when = parse_azure_time(props.get("startTime"))

            if status not in SUCCESS_STATUSES:
                failed = failed + 1
                errors = props.get("errorDetails")
                detail = ""
                if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                    detail = " - " + str(errors[0].get("errorTitle", ""))
                findings.append("Restore attempt did not succeed: " + describe(props) + detail)
            elif when is None or when < cutoff:
                stale = stale + 1
                findings.append("Successful restore outside the "
                                + str(RECENCY_DAYS) + "-day window: " + describe(props))
            else:
                qualifying = qualifying + 1
                if newest is None or when > newest:
                    newest = when
                    newest_label = describe(props)

        is_backup_tested = qualifying > 0

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if is_backup_tested:
            age = (now - newest).days
            pass_reasons.append(
                "Backup recoverability verified by restore test " + newest_label
                + ", " + str(age) + " days ago"
            )
        else:
            if failed > 0 and qualifying == 0 and stale == 0:
                fail_reasons.append(
                    "Restore tests were attempted (" + str(failed)
                    + ") but none completed successfully"
                )
            elif stale > 0:
                fail_reasons.append(
                    "No successful restore test within the last "
                    + str(RECENCY_DAYS) + " days; most recent success is older"
                )
            else:
                fail_reasons.append(
                    "No successful restore test found in the last "
                    + str(RECENCY_DAYS) + " days"
                )
            recommendations.append(
                "Perform a restore of a representative protected item and confirm it "
                "completes successfully. A restore into an isolated resource group, or "
                "an item-level file recovery, is sufficient evidence."
            )

        return create_response(
            result={criteriaKey: is_backup_tested},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={
                "restoreJobsFound": len(jobs),
                "qualifyingRestores": qualifying,
                "successfulButStale": stale,
                "unsuccessfulRestores": failed,
                "recencyWindowDays": RECENCY_DAYS
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
