"""
Transformation: criticalOpenFindingsCount
Vendor: Amazon GuardDuty  |  Category: Cloud Security

Integration-Service workflow getGuardDutyOpenFindingStatistics, legs:
  detectorIds                 <- listGuardDutyDetectors: GET /detector
  detectors                   <- getGuardDutyDetector: GET /detector/{detectorId}, per detector
  findingStatisticsByDetector <- getGuardDutyFindingStatistics: POST /detector/{detectorId}/findings/statistics
                                 {"findingCriteria": {"criterion": {"service.archived": {"eq": ["false"]}}},
                                  "groupBy": "SEVERITY", "maxResults": 100}, per detector
  https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindingsStatistics.html
  Severity bands (GuardDuty user guide): Low 1.0-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0.

The number of open (unarchived) GuardDuty findings with severity 9.0 and above (the Critical band),
summed over the detectors in the connected Region.

Fail closed (Not evaluated, never a pass):
- a failed, refused (401/403), error-shaped or unrecognised read is null, never 0;
- no detector, or a suspended detector, is null: a detector that is not running raises no
  findings, so 0 would prove nothing (isGuardDutyEnabled reports that state);
- a statistics response that may be partial (a nextToken, or 100 severity groups, the page
  limit) is null;
- one statistics response per detector, or null.
"""

import json
from datetime import datetime, timezone

VENDOR = "Amazon GuardDuty"
CATEGORY = "Cloud Security"
WRAPPERS = ("data", "response", "result", "apiResponse", "Output")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def unwrap(data, keys):
    """The first dict (under the usual Integration-Service wrappers) that carries one of keys."""
    for depth in range(6):
        if not isinstance(data, dict):
            return None
        for key in keys:
            if key in data:
                return data
        nxt = None
        for key in WRAPPERS:
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def error_text(body):
    """Why a body is an error, or None. Integration-Service envelopes and AWS rest-json error
    bodies ({"__type": ...}, {"message": ...}) both count."""
    if not isinstance(body, dict):
        return "not an object"
    if body.get("error") is True or body.get("errorType") or body.get("status") == "Error":
        return "Integration-Service error " + str(body.get("statusCode") or "") + ": " + str(
            body.get("message") or body.get("errorMessage") or "")[:200]
    if body.get("__type"):
        return "AWS error " + str(body.get("__type"))[:120]
    return None


def to_float(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def to_int(value):
    number = to_float(value)
    if number is None or number < 0 or number != int(number):
        return None
    return int(number)


def load_detectors(input):
    """(ids, detectors, problem) from a GuardDuty workflow output:
      detectorIds <- ListDetectors (GET /detector)
      detectors   <- GetDetector, one response per detector id (iterate step)
    ids == [] is a complete answer: there is no detector in the connected Region."""
    legs = unwrap(parse(input), ("detectorIds",))
    if legs is None:
        data = unwrap(parse(input), ("__type", "error", "errorType", "message"))
        problem = error_text(data) if data is not None else None
        return None, None, "ListDetectors: " + (problem or "no GuardDuty detector list in the response")
    problem = error_text(legs)
    if problem:
        return None, None, "ListDetectors: " + problem
    ids = legs.get("detectorIds")
    if not isinstance(ids, list) or not all([isinstance(i, str) and i for i in ids]):
        return None, None, "ListDetectors: unreadable detectorIds"
    if legs.get("nextToken"):
        return None, None, "ListDetectors returned more pages than were read"
    if not ids:
        return [], [], None
    detectors = legs.get("detectors")
    if isinstance(detectors, dict):
        detectors = [detectors]
    if not isinstance(detectors, list):
        return None, None, "GetDetector: not returned"
    if len(detectors) != len(ids):
        return None, None, "GetDetector: " + str(len(detectors)) + " responses for " + str(len(ids)) + " detector(s)"
    for body in detectors:
        problem = error_text(body)
        if problem:
            return None, None, "GetDetector: " + problem
        if str(body.get("status") or "").upper() not in ("ENABLED", "DISABLED"):
            return None, None, "GetDetector: no readable detector status"
    return ids, detectors, None


def is_enabled(detector):
    return str(detector.get("status") or "").upper() == "ENABLED"


def feature_states(detector, names):
    """Statuses (ENABLED/DISABLED) of the named detector features, in the order found."""
    out = []
    features = detector.get("features")
    if not isinstance(features, list):
        return out
    for feature in features:
        if isinstance(feature, dict) and str(feature.get("name") or "").upper() in names:
            out.append(str(feature.get("status") or "").upper())
    return out


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id=""):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }


KEY = "criticalOpenFindingsCount"
LOW = 9.0
HIGH = 1000.0
LABEL = "Critical"
BAND = "9.0 and above"
GROUP_LIMIT = 100


def band_count(stats):
    """(count, problem) for one GetFindingsStatistics body."""
    problem = error_text(stats)
    if problem:
        return None, problem
    if stats.get("nextToken"):
        return None, "the statistics response has more pages than were read"
    body = stats.get("findingStatistics")
    if not isinstance(body, dict):
        return None, "no findingStatistics in the response"
    total = 0
    grouped = body.get("groupedBySeverity")
    if isinstance(grouped, list):
        if len(grouped) >= GROUP_LIMIT:
            return None, str(len(grouped)) + " severity groups (the page limit), so the statistics may be partial"
        for group in grouped:
            if not isinstance(group, dict):
                return None, "unreadable severity group"
            severity = to_float(group.get("severity"))
            count = to_int(group.get("totalFindings"))
            if severity is None or count is None:
                return None, "a severity group without a severity or a count"
            if LOW <= severity < HIGH:
                total = total + count
        return total, None
    legacy = body.get("countBySeverity")
    if isinstance(legacy, dict):
        for name in legacy:
            severity = to_float(name)
            count = to_int(legacy[name])
            if severity is None or count is None:
                return None, "a severity bucket without a severity or a count"
            if LOW <= severity < HIGH:
                total = total + count
        return total, None
    return None, "no groupedBySeverity or countBySeverity in the response"


def transform(input):
    try:
        ids, detectors, problem = load_detectors(input)
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=KEY)
        if not ids:
            return build_response({KEY: None}, errors=[
                "GuardDuty has no detector in the connected Region, so it raises no findings there; "
                "zero findings would prove nothing"], transform_id=KEY)
        off = [ids[i] for i in range(len(ids)) if not is_enabled(detectors[i])]
        if off:
            return build_response({KEY: None}, errors=[
                "GuardDuty detector " + ", ".join(off) + " is suspended, so it raises no new findings; "
                "zero findings would prove nothing"], transform_id=KEY)
        legs = unwrap(parse(input), ("detectorIds",))
        stats = legs.get("findingStatisticsByDetector")
        if isinstance(stats, dict):
            stats = [stats]
        if not isinstance(stats, list) or len(stats) != len(ids):
            return build_response({KEY: None}, errors=[
                "GetFindingsStatistics: " + (str(len(stats)) + " responses for " + str(len(ids)) + " detector(s)"
                                            if isinstance(stats, list) else "not returned")], transform_id=KEY)
        total = 0
        for i in range(len(ids)):
            count, problem = band_count(stats[i])
            if problem:
                return build_response({KEY: None}, errors=["GetFindingsStatistics (" + ids[i] + "): " + problem],
                                      transform_id=KEY)
            total = total + count
        summary = {"detectors": len(ids), "openFindingsInBand": total}
        if total:
            return build_response({KEY: total}, fail_reasons=[
                str(total) + " open " + LABEL + " GuardDuty finding(s) (severity " + BAND + ", unarchived) on detector " +
                ", ".join(ids)], summary=summary,
                recommendations=["Investigate and resolve or archive the open " + LABEL + " GuardDuty findings."],
                transform_id=KEY)
        return build_response({KEY: 0}, pass_reasons=[
            "No open " + LABEL + " GuardDuty findings on enabled detector " + ", ".join(ids)], summary=summary,
            transform_id=KEY)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)[:300]], transform_id=KEY)
