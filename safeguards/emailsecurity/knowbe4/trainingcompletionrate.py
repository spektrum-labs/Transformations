# trainingcompletionrate.py - KnowBe4 (Email Security, 8a2164ea)
#
# Method: getTrainingEnrollments -> GET {serverUrl}/v1/training/enrollments?exclude_archived_users=true
#         (page/per_page, all pages)
# Docs:   https://developer.knowbe4.com/rest/reporting (spec /elvis-swagger.yml)
#           Enrollment.status "Completion status. (Not Started, In Progress, Completed, Passed, Past Due)"

import json


def transform(input):
    """
    Completed or Passed enrollments / all enrollments of non-archived users x 100, to 2 decimals.

    None when the body is not an enrollment list, the list is empty, or any enrollment carries a
    status outside the documented five (the rate would then be a guess).
    """
    key = "trainingCompletionRate"
    done = ["completed", "passed"]
    known = ["not started", "in progress", "completed", "passed", "past due"]

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    def unwrap(value):
        for depth in range(4):
            if not isinstance(value, dict):
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(w), (dict, list)):
                    value = value[w]
                    moved = True
                    break
            if not moved:
                break
        return value

    try:
        data = unwrap(parse(input))
        if not isinstance(data, list):
            return {key: None, "reason": "Response is not a KnowBe4 training enrollment list"}
        if not data:
            return {key: None, "reason": "No training enrollments"}
        completed = 0
        for e in data:
            status = str((e or {}).get("status") or "").strip().lower() if isinstance(e, dict) else ""
            if status not in known:
                return {key: None, "reason": "Enrollment with an undocumented status", "status": status}
            if status in done:
                completed = completed + 1
        return {key: round(completed * 100.0 / len(data), 2), "completedEnrollments": completed, "totalEnrollments": len(data)}
    except Exception as e:
        return {key: None, "error": str(e)}
