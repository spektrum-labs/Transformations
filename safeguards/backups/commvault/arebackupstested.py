# arebackupstested.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getRestoreJobs -> GET {serverUrl}/Job?jobFilter=Restore&jobCategory=Finished&completedJobLookupTime=7776000
#         (header limit: 1000; Accept: application/json)
# Docs:   https://documentation.commvault.com/11.40/software/rest_api_get_job.html
#         (totalRecordsWithoutPaging; jobs[].jobSummary: jobId, jobType, status, jobStartTime; job status values
#         Completed, Completed w/ one or more errors|warnings, Committed, Failed, Failed to Start, Killed, ...)
# The server applies the time window and the finished-only filter. A body whose job list is shorter than
# totalRecordsWithoutPaging (an unread page) is refused, never read as "no failures".
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    areBackupsTested = true when at least one restore job ended Completed (or with warnings) in the last 90 days:
    a backup was actually recovered. Does not prove the restore was a planned test or covered every workload.
    """
    key = "areBackupsTested"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("XML body; the method must send Accept: application/json")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        # Integration-Service may hand the body back under one of its envelopes.
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

    def vendor_error(d):
        """A reason string when the body is an Integration-Service or Commvault error, else None.
        Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        code = d.get("errorCode")
        if code not in (None, 0, "0"):
            return "Commvault error " + str(code) + ": " + str(d.get("errorMessage") or "")
        errs = d.get("errList")
        if isinstance(errs, list) and len(errs) > 0:
            return "Commvault errList: " + str(errs[0])[:200]
        err = d.get("error")
        if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
            return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")
        return None

    def as_int(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        return None

    SUCCESS = ["completed", "completed w/ one or more warnings"]
    FAILURE = ["failed", "failed to start", "killed", "abnormal terminated cleanup",
               "completed w/ one or more errors", "committed", "interrupted"]
    ACTIVE = ["running", "waiting", "pending", "suspend", "suspended", "kill pending",
              "interrupt pending", "queued", "running (cannot be verified)"]

    def read_jobs(input):
        """(summaries, None) or (None, reason). Refuses a body whose job list is shorter than
        totalRecordsWithoutPaging: a page that was not read is not a page with no failures."""
        data = unwrap(parse_input(input), "totalRecordsWithoutPaging")
        problem = vendor_error(data)
        if problem:
            return None, problem
        total = as_int(data.get("totalRecordsWithoutPaging"))
        if total is None:
            return None, "Response has no totalRecordsWithoutPaging, so it is not a Commvault job list"
        jobs = data.get("jobs")
        if jobs is None:
            jobs = []
        if not isinstance(jobs, list):
            return None, "jobs has an unexpected shape"
        if len(jobs) < total:
            return None, "Read " + str(len(jobs)) + " of " + str(total) + " jobs; the remaining pages were not read"
        rows = []
        for j in jobs:
            s = j.get("jobSummary") if isinstance(j, dict) else None
            if not isinstance(s, dict):
                return None, "A job has no jobSummary object"
            rows.append(s)
        return rows, None

    def classify(rows):
        """Counts finished jobs by outcome. unknown = a terminal status this check does not know."""
        out = {"success": [], "failure": [], "active": [], "unknown": []}
        for s in rows:
            st = str(s.get("status") or "").strip().lower()
            if st in SUCCESS:
                out["success"].append(s)
            elif st in FAILURE:
                out["failure"].append(s)
            elif st in ACTIVE:
                out["active"].append(s)
            else:
                out["unknown"].append(s)
        return out

    def label(s):
        sub = s.get("subclient") if isinstance(s.get("subclient"), dict) else {}
        client = sub.get("clientName") or s.get("destClientName") or s.get("clientName") or "?"
        name = sub.get("subclientName") or s.get("subclientName") or ""
        return str(client) + ("/" + str(name) if name else "") + " job " + str(s.get("jobId")) + " (" + str(s.get("status")) + ")"

    try:
        rows, problem = read_jobs(input)
        if rows is None:
            return {key: False, "reason": problem}
        c = classify(rows)
        ok = [s for s in c["success"] if "restore" in str(s.get("jobType") or "restore").lower()]
        if len(ok) == 0:
            return {key: False, "reason": "No restore job completed in the last 90 days (" + str(len(rows)) + " finished restore jobs read)"}
        return {key: True, "reason": str(len(ok)) + " restore jobs completed in the last 90 days", "latest": label(ok[0])}
    except Exception as e:
        return {key: False, "error": str(e)}
