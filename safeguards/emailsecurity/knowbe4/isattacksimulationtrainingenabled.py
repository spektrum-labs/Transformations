# isattacksimulationtrainingenabled.py - KnowBe4 (Email Security, 8a2164ea)
#
# Method: getPhishingSecurityTests -> GET {serverUrl}/v1/phishing/security_tests (page/per_page, all pages)
# Docs:   https://developer.knowbe4.com/rest/reporting (spec /elvis-swagger.yml)
#           /v1/phishing/security_tests "retrieves a list of all phishing security tests"
#           PST.started_at "Date and time the phishing security test started"

import json
import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isAttackSimulationTrainingEnabled',)


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
    True when at least one phishing security test started in the last 90 days: simulated
    phishing is actually running, not merely configured once. False on an empty list or on
    tests that are all older. None (Not evaluated) on a body that is not a test list (an error,
    an empty or an unrecognised body) and on a list in which a test has no start date that can be
    read and no readable test is recent: the unreadable test could be the recent one, so "no
    simulation is running" is not proven. A recent test is True whatever else is in the list.
    The reasons are fixed text: exception and vendor text are never repeated.
    """
    key = "isAttackSimulationTrainingEnabled"
    window_days = 90

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
        if not isinstance(text, str) or not text.strip():
            return None
        try:
            t = datetime.datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        return t

    try:
        data = unwrap(parse(input))
        if not isinstance(data, list):
            return {key: None, "reason": "Response is not a KnowBe4 phishing security test list"}
        now = datetime.datetime.now(datetime.timezone.utc)
        recent = 0
        unreadable = 0
        for t in data:
            started = when(t.get("started_at")) if isinstance(t, dict) else None
            if started is None:
                unreadable = unreadable + 1
            elif (now - started).days <= window_days and started <= now:
                recent = recent + 1
        if recent:
            return {key: True, "reason": "Phishing security tests started in the last 90 days", "recentTests": recent, "totalTests": len(data)}
        if unreadable:
            return {key: None, "reason": "%d of %d phishing security test(s) have no start date that could be read, so it cannot be confirmed that no simulation ran in the last 90 days." % (unreadable, len(data))}
        return {key: False, "reason": "No phishing security test started in the last 90 days", "totalTests": len(data)}
    except Exception:
        return {key: None, "reason": "The KnowBe4 phishing security test response could not be read, so simulations were not evaluated."}


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
