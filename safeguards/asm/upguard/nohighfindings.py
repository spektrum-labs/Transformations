# nohighfindings.py - UpGuard (Attack Surface Management, c2104db1)
#
# Method: getRisks -> GET https://cyber-risk.upguard.com/api/public/risks?min_severity=high
# Docs:   https://cyber-risk.upguard.com/api/docs (spec /api/swagger.json)
#           GET /risks "Returns a list of risks that have been detected for your account."
#           min_severity enum info|low|medium|high|critical; Risk.severity "The risk severity"
#           Required API key permission: BreachRisk

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('noHighFindings',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


#: The one count the vendor's public API spec documents (on the domain list). The risk and vulnerability
#: lists document no count.
COUNT_KEY = "total_results"
NEXT_PAGE_KEYS = ("next_page_token", "nextPageToken", "next_page", "next")


def read_has_error(levels):
    """True when the body, or a wrapper around it, carries an error marker.

    A body with an error beside the list is not the vendor's answer, so nothing is read from it.
    """
    for level in levels:
        if isinstance(level, dict) and (level.get("error") or level.get("errors")):
            return True
    return False


def read_has_next_page(levels):
    """True when the body, or a wrapper around it, points at a further page.

    A page that is not the last holds only some of the records. A result that rests on ABSENCE (a pass,
    "none found", a total count) is not evidence there: the record that would change it may be on a
    page that was not read. A negative proven by a record already seen still holds, but what was seen
    is not a total, so no count is reported with it.
    """
    for level in levels:
        if not isinstance(level, dict):
            continue
        for k in NEXT_PAGE_KEYS:
            if level.get(k):
                return True
    return False


def empty_list_is_complete(data, count_documented):
    """True when an empty list (on a body with no error and no next page) is a real answer.

    Never when it states a count that is not a whole number 0 (a bool or text count, or a count above 0).
    Where the vendor documents a count for the endpoint (count_documented), the body must state it
    as 0. Where it documents none, the empty list on the last page is the vendor's own answer for
    an account with nothing to report.
    """
    if not isinstance(data, dict):
        return False
    count = data.get(COUNT_KEY)
    if count is None:
        return not count_documented
    return isinstance(count, int) and not isinstance(count, bool) and count == 0


def transform_unmarked(input):
    """
    True when the account's active risk list (severity high and above) holds no risk rated high.

    Waived risks still count: a waiver is an accepted risk, not a closed one.
    False when any risk carries a severity outside the documented enum (it could be high).
    None (not evaluated) when the body, or a wrapper around it, carries an error marker. On a page that is not
    the last (a next-page token), a result that rests on absence is not evidence: None when no high risk was
    seen, and False without a total when one was (a risk already seen proves the negative). Also None when
    the body has no risks list, holds no object record, is an empty list with a count above 0, or cannot be
    read. The vendor documents no count for this list, so an empty list on the last page is a clean account.
    """
    key = "noHighFindings"
    documented = ["info", "low", "medium", "high", "critical"]

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    def unwrap(value, marker):
        levels = []
        for depth in range(4):
            levels.append(value)
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(w), dict):
                    value = value[w]
                    moved = True
                    break
            if not moved:
                break
        if levels[-1] is not value:
            levels.append(value)
        return value, levels

    try:
        data, levels = unwrap(parse(input), "risks")
        if not isinstance(data, dict) or not isinstance(data.get("risks"), list):
            return {key: None, "reason": "Response has no risks list (the /risks call did not run)"}
        if read_has_error(levels):
            return {key: None, "reason": "The response carries an error marker, so it is not evaluated"}
        more = read_has_next_page(levels)
        if data["risks"] and not any(isinstance(r, dict) for r in data["risks"]):
            return {key: None, "reason": "Risk list holds no object record"}
        if not data["risks"] and (more or not empty_list_is_complete(data, False)):
            return {key: None, "reason": "Risk list is empty but the response is not a complete answer (a next page, or a count above 0), so it is not read as no open risks"}
        hits = 0
        for r in data["risks"]:
            sev = str((r.get("severity") if isinstance(r, dict) else "") or "").strip().lower()
            if sev not in documented:
                return {key: False, "reason": "A risk has an undocumented severity", "severity": sev}
            if sev == "high":
                hits = hits + 1
        if hits and more:
            return {key: False, "reason": "An open high risk was seen on a page that is not the last, so the total is not known"}
        if hits:
            return {key: False, "reason": "Open high risks detected", "count": hits, "riskCount": len(data["risks"])}
        if more:
            return {key: None, "reason": "No high risk was seen, but the page is not the last, so it is not read as no open high risks"}
        return {key: True, "reason": "No open high risks", "riskCount": len(data["risks"])}
    except Exception:
        return {key: None, "error": "The response could not be read, so it was not evaluated."}


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
