# trainingcompletionrate.py - KnowBe4 (Email Security, 8a2164ea)
#
# Method: getTrainingEnrollments -> GET {serverUrl}/v1/training/enrollments?exclude_archived_users=true
#         (page/per_page, all pages)
# Docs:   https://developer.knowbe4.com/rest/reporting (spec /elvis-swagger.yml)
#           Enrollment.status "Completion status. (Not Started, In Progress, Completed, Passed, Past Due)"

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('trainingCompletionRate',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


def transform_unmarked(input):
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


def transform(input):
    """transform_unmarked(), with a None criterion reported as not evaluated.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". This file's responses do not set that status, so it is set here, carrying the
    file's own reason for the None.
    """
    out = transform_unmarked(input)
    if not isinstance(out, dict):
        return out
    inner = out.get("transformedResponse", out)
    if not isinstance(inner, dict) or not criteria_unmeasured(inner):
        return out
    info = out.get("additionalInfo")
    info = info if isinstance(info, dict) else {}
    collection = info.get("dataCollection")
    if isinstance(collection, dict) and str(collection.get("status") or "").lower() == "error":
        return out
    evaluation = info.get("evaluation")
    reasons = evaluation.get("failReasons") if isinstance(evaluation, dict) else None
    why = [str(r) for r in reasons if r] if isinstance(reasons, list) else []
    for k in ("reason", "error", "unevaluated"):
        if out.get(k) and str(out.get(k)) not in why:
            why = why + [str(out.get(k))]
    errors = collection.get("errors") if isinstance(collection, dict) else None
    why = why + [str(e) for e in errors if e] if isinstance(errors, list) else why
    marked = dict(collection if isinstance(collection, dict) else {}, status="error",
                  errors=why or ["The response could not answer this check, so it was not evaluated."])
    return dict(out, additionalInfo=dict(info, dataCollection=marked))
