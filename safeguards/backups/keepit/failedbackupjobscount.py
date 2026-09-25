# failedbackupjobscount.py - Keepit
#
# Method: getDeviceJobs (Integration-Service workflow)
#   1. listDevices    -> GET {serverUrl}/users/{accountId}/devices
#   2. listDeviceJobs -> GET {serverUrl}/users/{accountId}/devices/{guid}/jobs, once per
#      cloud connector (workflow "iterate" over devices.cloud), collected under "deviceJobs"
# Docs:   https://developers.keepit.com/api/data-protection/connectors#list-devices
#         https://developers.keepit.com/api/data-protection/connectors#list-device-jobs
#         ("By default, the response includes jobs from a window of +/-7 days relative to the
#         current time"); schema "jobs" (job.type, job.state, job.started, job.succeeded,
#         job.failed, job.cancelled) at https://developers.keepit.com/api/data-protection/~schemas
#
# Keepit answers in XML only; Integration-Service parses it with xmltodict, so one element is a
# dict, several are a list, an empty element is None and booleans are "true"/"false" strings.
# A job counts as a backup job when <type> is "backup" (or, with no <type>, its description
# says backup). Terminal states: successful, unsuccessful, incomplete, cancelled.

import json


def transform(input):
    """
    Returns failedBackupJobsCount = the number of Keepit backup jobs, across every cloud
    connector, that ended unsuccessful or incomplete in the /jobs window (the last 7 days).
    The requirement compares with isEquals "0".

    Proves: Keepit's own job records for every connector were read and N of them failed.
    Does not prove: anything outside the 7-day window. Returns None (no evidence) when the
    body is unreadable, a connector's /jobs was not read, or no backup job finished at all,
    so an empty or broken read never reports zero failures.
    """
    key = "failedBackupJobsCount"

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
        rows, problem = read_connectors(input)
        if rows is None:
            return {key: None, "reason": problem}
        if len(rows) == 0:
            return {key: None, "reason": "The account has no cloud connectors, so there are no backup jobs to count"}
        terminal = sum([r["terminal"] for r in rows])
        if terminal == 0:
            return {key: None, "reason": "No backup job finished in the /jobs window on any connector; the count is not proven", "connectorCount": len(rows)}
        unsuccessful = sum([r["counts"]["unsuccessful"] for r in rows])
        incomplete = sum([r["counts"]["incomplete"] for r in rows])
        failed = unsuccessful + incomplete
        per = {}
        for r in rows:
            n = r["counts"]["unsuccessful"] + r["counts"]["incomplete"]
            if n > 0:
                per[r["connector"]] = n
        return {
            key: failed,
            "reason": str(failed) + " of " + str(terminal) + " finished backup jobs across " + str(len(rows)) + " connectors ended unsuccessful or incomplete",
            "unsuccessfulJobs": unsuccessful,
            "incompleteJobs": incomplete,
            "finishedBackupJobs": terminal,
            "failedJobsByConnector": per,
        }
    except Exception as e:
        return {key: None, "error": str(e)}
