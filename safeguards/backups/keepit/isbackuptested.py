# isbackuptested.py - Keepit
#
# Method: getDeviceJobs (Integration-Service workflow, the one staleprotectionjobscount.py reads)
#   1. listDevices    -> GET {serverUrl}/users/{accountId}/devices
#   2. listDeviceJobs -> GET {serverUrl}/users/{accountId}/devices/{guid}/jobs, once per cloud connector
#      (workflow "iterate" over devices.cloud), collected under "deviceJobs"
# Docs:   https://developers.keepit.com/api/data-protection/connectors#list-device-jobs ("By default, the response
#         includes jobs from a window of +/-7 days relative to the current time"); job.type is one of backup,
#         restore, srestore (selective restore); a finished job carries succeeded or failed (or cancelled).
#
# isBackupTested is True when at least one restore or selective-restore job SUCCEEDED in the jobs window on any
# cloud connector: a backup was restored from and the restore completed. The window is the vendor's +/-7 days and
# no documented parameter widens it, so the absence of a restore in it says nothing about the requirement's
# defined period: the key is then not evaluated (None, dataCollection error), never False. Failed or cancelled
# restores in the window are reported as findings. Not evaluated also when the body is unreadable, a connector's
# /jobs was not read, or the account has no cloud connectors.

import json
from datetime import datetime

KEY = "isBackupTested"
RESTORE_TYPES = ["restore", "srestore"]


def respond(value, extra=None, problem=None, pass_reasons=None, findings=None):
    result = {KEY: value}
    for k in (extra or {}):
        result[k] = extra[k]
    errors = [problem] if problem else []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if problem else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": extra or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": errors, "recommendations": [],
                           "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": "Keepit", "category": "backups"},
        },
    }


def transform(input):
    """isBackupTested from the Keepit per-connector job lists (see the header)."""
    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("raw XML body was not parsed by Integration-Service")
            return json.loads(text)
        return value

    def listify(value):
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return value
        return [value]

    def unwrap(value, marker):
        # Integration-Service may hand a step's body back under one of its envelopes.
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def as_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low == "true":
                return True
            if low == "false":
                return False
        return None

    def job_state(job):
        # <state> is the documented lifecycle; older jobs may carry only the timestamps.
        state = str(job.get("state") or "").strip().lower()
        if state:
            return state
        if job.get("succeeded"):
            return "successful"
        if job.get("failed"):
            return "unsuccessful"
        if job.get("cancelled"):
            return "cancelled"
        if as_bool(job.get("active")) is True:
            return "in-progress"
        return ""

    def is_backup_job(job):
        kind = str(job.get("type") or "").strip().lower()
        if kind:
            return kind == "backup"
        return "backup" in str(job.get("description") or "").lower()

    def read_connectors(input):
        """Pairs each cloud connector from listDevices with its own /jobs body.

        Returns (rows, None) or (None, reason). The workflow calls /jobs once per connector in
        the order listDevices returned them, so the two lists must be the same length; any
        mismatch means part of the estate was not read, and nothing is claimed.
        """
        data = unwrap(parse_input(input), "devices")
        if not isinstance(data, dict):
            return None, "Response is not an object"
        if data.get("error") is True:
            return None, "Integration-Service returned an error envelope"
        if "devices" not in data:
            return None, "Response has no <devices> element, so no connector could be read"
        if "deviceJobs" not in data:
            return None, "Response has no deviceJobs (the per-connector /jobs step did not run)"
        devices = data.get("devices")
        if devices is None or devices == "":
            devices = {}
        if not isinstance(devices, dict):
            return None, "<devices> element has an unexpected shape"
        clouds = [c for c in listify(devices.get("cloud")) if isinstance(c, dict)]
        bodies = listify(data.get("deviceJobs"))
        if len(bodies) != len(clouds):
            return None, "Read /jobs for " + str(len(bodies)) + " connectors but listDevices returned " + str(len(clouds))
        rows = []
        for i in range(len(clouds)):
            c = clouds[i]
            body = unwrap(bodies[i], "jobs")
            if not isinstance(body, dict) or "jobs" not in body:
                return None, "Connector " + str(c.get("name") or c.get("guid")) + ": /jobs body has no <jobs> element"
            if body.get("error") is True:
                return None, "Connector " + str(c.get("name") or c.get("guid")) + ": /jobs returned an error"
            jobs_el = body.get("jobs")
            if jobs_el is None or jobs_el == "":
                jobs_el = {}
            if not isinstance(jobs_el, dict):
                return None, "Connector " + str(c.get("name") or c.get("guid")) + ": <jobs> has an unexpected shape"
            jobs = [j for j in listify(jobs_el.get("job")) if isinstance(j, dict)]
            backups = [j for j in jobs if is_backup_job(j)]
            counts = {"successful": 0, "unsuccessful": 0, "incomplete": 0, "cancelled": 0}
            for j in backups:
                s = job_state(j)
                if s in counts:
                    counts[s] = counts[s] + 1
            name = str(c.get("name") or c.get("guid") or "")
            kind = str(c.get("type") or "")
            rows.append({
                "connector": name + " (" + kind + ")" if kind else name,
                "jobs": jobs,
                "backupJobs": backups,
                "counts": counts,
                "terminal": counts["successful"] + counts["unsuccessful"] + counts["incomplete"] + counts["cancelled"],
            })
        return rows, None

    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            input = input.get("data")
        rows, problem = read_connectors(input)
        if rows is None:
            return respond(None, problem=problem)
        if len(rows) == 0:
            return respond(None, problem="The account has no cloud connectors, so no restore can be shown")
        succeeded = []
        failed = []
        for r in rows:
            for j in r["jobs"]:
                if str(j.get("type") or "").strip().lower() not in RESTORE_TYPES:
                    continue
                state = job_state(j)
                label = r["connector"] + " " + str(j.get("type")) + " " + str(j.get("started") or j.get("start") or j.get("scheduled") or "")
                if state == "successful":
                    succeeded.append(label)
                elif state in ("unsuccessful", "incomplete", "cancelled"):
                    failed.append(label + " (" + state + ")")
        extra = {"connectorCount": len(rows), "succeededRestores": len(succeeded), "failedRestores": len(failed)}
        findings = ["Restores that did not complete: " + "; ".join(failed[:5])] if failed else []
        if succeeded:
            return respond(True, extra, pass_reasons=[str(len(succeeded)) + " restore job(s) completed in the Keepit jobs window: " +
                                                      "; ".join(succeeded[:3])], findings=findings)
        return respond(None, extra, problem=("No restore job completed in the Keepit jobs window (+/-7 days, " + str(len(failed)) +
                                             " failed or cancelled); a restore earlier in the defined period cannot be seen"),
                       findings=findings)
    except Exception as e:
        return respond(None, problem="Transformation error: " + str(e))
