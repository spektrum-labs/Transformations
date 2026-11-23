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

Not evaluated (None, with a collection error) when the read proves no absence:
no vault was read, or the restore jobs of at least one vault were not read in
full (an error, anything but a job list, or a page with a next-page link) and
no job that was read shows a recent successful restore. A restore that did
succeed is proof whatever else failed to read. A vault that was read in full
and holds no restore job is a real False.
"""

import json
from datetime import datetime, timedelta

SUCCESS_STATUSES = ["Completed", "CompletedWithWarnings"]
RECENCY_DAYS = 365
MAX_WALK_DEPTH = 6
ERROR_TEXT_LIMIT = 200
PAGE_LINK_KEYS = ["nextLink", "@odata.nextLink", "skipToken", "$skipToken"]


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
    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get("isBackupTested") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["isBackupTested could not be measured from the response"]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else not_measured_reasons
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


def job_collection_seen(node, depth):
    """True when the payload carries a restore-job collection whose emptiness is PROVEN.

    An ARM list -- restoreJobResults, restoreJobs, value -- answers 403 on a scope the
    caller cannot read, so an empty one is a measured "no restore jobs". A Resource Graph
    table is NOT such a collection when its rows are empty: Resource Graph is RBAC-scoped
    and a partially readable scope answers 200 with only the readable subset and, in
    Microsoft's words, "without any indication that the result might be partial", so zero
    rows is equally "no restore job ran" and "the vaults are in a subscription this
    principal cannot read". A Resource Graph table therefore counts here only when it
    carries at least one row. See CONTRIBUTING.md, "Azure Resource Graph: zero rows is not
    a proven empty set".
    """
    if depth > MAX_WALK_DEPTH:
        return False
    if isinstance(node, list):
        for item in node:
            if job_collection_seen(item, depth + 1):
                return True
        return False
    if not isinstance(node, dict):
        return False
    for key in ["restoreJobResults", "restoreJobs", "value"]:
        if isinstance(node.get(key), list):
            return True
    if isinstance(node.get("columns"), list) and node.get("rows"):
        return True
    for key in ["apiResponse", "data"]:
        if key in node and job_collection_seen(node[key], depth + 1):
            return True
    return False


def refused(node, depth):
    """True when a vault's answer, or the raw body nested under it, is an error or an HTTP refusal."""
    if depth > MAX_WALK_DEPTH or not isinstance(node, dict):
        return False
    if node.get("error") or node.get("Error") or node.get("errors"):
        return True
    status = node.get("statusCode")
    if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
        return True
    for key in ["apiResponse", "data"]:
        if key in node and refused(node[key], depth + 1):
            return True
    return False


def vault_entries(node, depth):
    """The per-vault answers of the iterated restore-job read, or None when the payload is not that read.

    getRestoreJobStatus runs once per vault from listVaults, so the stored body is one ARM answer per
    vault under restoreJobResults: {"restoreJobResults": [{"value": [...]}, {"error": {...}}]}.
    """
    if depth > MAX_WALK_DEPTH:
        return None
    if isinstance(node, list):
        for item in node:
            found = vault_entries(item, depth + 1)
            if found is not None:
                return found
        return None
    if not isinstance(node, dict):
        return None
    if isinstance(node.get("restoreJobResults"), list):
        return node["restoreJobResults"]
    for key in ["apiResponse", "data"]:
        if key in node:
            found = vault_entries(node[key], depth + 1)
            if found is not None:
                return found
    return None


def has_next_page(node, depth):
    """True when a vault's answer, or the raw body nested under it, carries a next-page link or skip token.

    Such a page is the first of several: a restore job on a later page was not read, so the page proves no absence.
    """
    if depth > MAX_WALK_DEPTH or not isinstance(node, dict):
        return False
    for key in PAGE_LINK_KEYS:
        if node.get(key):
            return True
    for key in ["apiResponse", "data"]:
        if key in node and has_next_page(node[key], depth + 1):
            return True
    return False


def is_job_record(entry):
    """True when an entry under restoreJobResults is a restore job itself, not one vault's answer."""
    return isinstance(entry, dict) and isinstance(entry.get("properties"), dict)


def entry_is_read(entry):
    """True when one vault's answer is a complete restore-job list: a list of job objects, or an ARM body carrying one.

    Not read: an ARM error body, an HTTP refusal, text, null, an empty object, an empty list (what a failed call
    leaves behind when the response is defaulted), a list holding anything but job objects, and a list that has a
    next page. Such a vault's restore history was not read in full, so it says nothing about whether a restore ran there.
    """
    if isinstance(entry, list):
        if len(entry) == 0:
            return False
        for item in entry:
            if not is_job_record(item) or refused(item, 0):
                return False
        return True
    if not isinstance(entry, dict):
        return False
    if refused(entry, 0) or has_next_page(entry, 0):
        return False
    return job_collection_seen(entry, 0)


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
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        entries = vault_entries(data, 0)
        vaults_read = 0
        vaults_not_read = 0
        flat_list_counted = False
        if entries is not None:
            for entry in entries:
                if is_job_record(entry):
                    # job objects listed directly under restoreJobResults are one vault's job list
                    if not flat_list_counted:
                        flat_list_counted = True
                        vaults_read = vaults_read + 1
                elif entry_is_read(entry):
                    vaults_read = vaults_read + 1
                else:
                    vaults_not_read = vaults_not_read + 1
            if flat_list_counted and has_next_page(data, 0):
                # the flat job list has a next page: only its first page was read, so that vault was not read in full
                vaults_read = vaults_read - 1
                vaults_not_read = vaults_not_read + 1
            if len(entries) == 0:
                # The vault list is a Resource Graph read: zero vaults is equally "there are none"
                # and "they are in a subscription this principal cannot read", so no restore
                # history was read at all. See CONTRIBUTING.md, "Azure Resource Graph: zero rows
                # is not a proven empty set".
                return create_response(
                    result={criteriaKey: None},
                    validation=validation,
                    api_errors=["isBackupTested not evaluated: no vault was read, which is also what a "
                                "subscription this principal cannot read returns"],
                    recommendations=["Confirm the principal has at least Reader on every subscription "
                                     "holding a Recovery Services or Backup vault, then re-run the query."],
                    fail_reasons=["isBackupTested not evaluated: no vault was read"],
                    input_summary={"vaultsRead": 0, "vaultsNotRead": 0}
                )
        elif has_next_page(data, 0):
            # a single restore-job list that has a next page: the rest of it was not read
            vaults_not_read = 1

        found = {}
        collect_restore_jobs(data, found, 0)
        jobs = list(found.values())
        if not jobs:
            jobs = rows_from_arg_table(data)

        if not jobs and not job_collection_seen(data, 0):
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["isBackupTested not evaluated: no restore job list in the response, or a "
                            "Resource Graph table with zero rows, which is also what a subscription this "
                            "principal cannot read returns"],
                recommendations=["Confirm the principal has at least Reader on every subscription holding "
                                 "a Recovery Services or Backup vault, then re-run the query."],
                fail_reasons=["isBackupTested not evaluated: no restore job list in the response"]
            )

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

        if vaults_not_read > 0:
            counts = str(vaults_not_read) + " of " + str(vaults_read + vaults_not_read)
            if not is_backup_tested:
                # A vault whose restore jobs came back as an error says nothing about that vault, so
                # "no successful restore" is not proven while one is unread.
                return create_response(
                    result={criteriaKey: None},
                    validation=validation,
                    api_errors=["isBackupTested not evaluated: the restore jobs of " + counts
                                + " vaults could not be read in full, and none of the jobs that were read shows a "
                                "successful restore in the last " + str(RECENCY_DAYS) + " days"],
                    recommendations=["Confirm the principal can read backup jobs on every Recovery Services "
                                     "vault, then re-run the query."],
                    fail_reasons=["isBackupTested not evaluated: " + counts + " vaults could not be read in full"],
                    additional_findings=findings,
                    input_summary={
                        "vaultsRead": vaults_read,
                        "vaultsNotRead": vaults_not_read,
                        "restoreJobsFound": len(jobs),
                        "recencyWindowDays": RECENCY_DAYS
                    }
                )
            findings.append("The restore jobs of " + counts + " vaults were not read in full; this verdict rests on "
                            "the jobs that were read")

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

        summary = {
            "restoreJobsFound": len(jobs),
            "qualifyingRestores": qualifying,
            "successfulButStale": stale,
            "unsuccessfulRestores": failed,
            "recencyWindowDays": RECENCY_DAYS
        }
        if entries is not None or vaults_not_read > 0:
            summary["vaultsRead"] = vaults_read
            summary["vaultsNotRead"] = vaults_not_read

        return create_response(
            result={criteriaKey: is_backup_tested},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)[:ERROR_TEXT_LIMIT]],
            fail_reasons=["Transformation error: " + str(e)[:ERROR_TEXT_LIMIT]]
        )
