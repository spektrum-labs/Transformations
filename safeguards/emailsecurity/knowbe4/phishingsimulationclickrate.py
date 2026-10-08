# phishingsimulationclickrate.py - KnowBe4 (Email Security, 8a2164ea)
#
# Method: getPhishingSecurityTests -> GET {serverUrl}/v1/phishing/security_tests (page/per_page, all pages)
# Docs:   https://developer.knowbe4.com/rest/reporting (spec /elvis-swagger.yml)
#           PST.phish_prone_percentage "Phish-prone percentage on the test, shown in decimal format
#           (Example: 0.2 = 20%)"; PST.status (example "Closed"); PST.started_at

import json
import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('phishingSimulationClickRate',)


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
    Phish-prone percentage (0-100) of the most recently started Closed phishing security test.

    None when there is no Closed test, the latest one has no phish_prone_percentage, or the value
    is outside the documented 0-1 decimal range.
    """
    key = "phishingSimulationClickRate"

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

    def when(text):
        if not isinstance(text, str) or not text:
            return None
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        return t

    try:
        data = unwrap(parse(input))
        if not isinstance(data, list):
            return {key: None, "reason": "Response is not a KnowBe4 phishing security test list"}
        latest = None
        latest_at = None
        for t in data:
            if not isinstance(t, dict) or str(t.get("status") or "").strip().lower() != "closed":
                continue
            started = when(t.get("started_at"))
            if started is not None and (latest_at is None or started > latest_at):
                latest = t
                latest_at = started
        if latest is None:
            return {key: None, "reason": "No Closed phishing security test with a start time", "totalTests": len(data)}
        ppp = latest.get("phish_prone_percentage")
        if not isinstance(ppp, (int, float)) or isinstance(ppp, bool) or ppp < 0 or ppp > 1:
            return {key: None, "reason": "Latest Closed test has no phish_prone_percentage in the documented 0-1 range", "pstId": latest.get("pst_id")}
        return {key: round(float(ppp) * 100, 2), "pstId": latest.get("pst_id"), "startedAt": latest.get("started_at")}
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
