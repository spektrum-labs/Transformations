"""
Transformation: isBackupTested
Vendor: Druva (Data Security Cloud, Enterprise Workloads)  |  Category: Backups
Method: getRestoreActivity -> POST /platform/reporting/v1/reports/ewRestoreActivity
Evaluates: True when the Druva Restore Activity report shows at least one restore with status Successful that ended within the last 365 days.
Fails closed: a missing, error or unrecognised body returns False.
"""
import json
from datetime import datetime

CRITERIA_KEY = "isBackupTested"
FAIL_VALUE = False
RECOMMENDATION = "Run and document a Druva test restore at least once a year."


WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output"]


def extract_input(input_data):
    """Decode the body and unwrap Spektrum envelopes. Undecodable input raises; transform() catches it and fails closed."""
    data = input_data
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if isinstance(data, str):
        data = json.loads(data)
    if isinstance(data, dict) and "validation" in data and "data" in data and isinstance(data.get("validation"), dict):
        return data["data"], data["validation"]
    if isinstance(data, dict):
        for depth in range(3):
            unwrapped = False
            for key in WRAPPER_KEYS:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": []}


def report_records(data):
    """Rows of a Druva Reports API response (POST /platform/reporting/v1/reports/{reportID}).

    Documented envelope: {"data": [...], "lastSyncTimestamp": "...", "filters": {...},
    "nextPageToken": "..."}. Anything else (error envelope, null, unrelated JSON) returns
    None, which every caller treats as NO EVIDENCE.
    """
    if not isinstance(data, dict):
        return None
    rows = data.get("data")
    if not isinstance(rows, list):
        return None
    if "lastSyncTimestamp" not in data:
        return None
    return [r for r in rows if isinstance(r, dict)]


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": CRITERIA_KEY, "vendor": "Druva", "category": "Backups"}
        }
    }


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response({CRITERIA_KEY: FAIL_VALUE}, validation, fail_reasons=["Input validation failed"])
        records = report_records(data)
        if records is None:
            return create_response(
                {CRITERIA_KEY: FAIL_VALUE}, validation,
                fail_reasons=["Response is not a Druva Reports API envelope (data + lastSyncTimestamp); nothing was proven"],
                recommendations=[RECOMMENDATION])
        value, summary, reasons = evaluate(records)
        passed = value is not None and value is not False
        return create_response(
            {CRITERIA_KEY: value, **summary}, validation,
            pass_reasons=reasons if passed else [],
            fail_reasons=[] if passed else reasons,
            recommendations=[] if passed else [RECOMMENDATION],
            input_summary=summary)
    except Exception as e:
        return create_response({CRITERIA_KEY: FAIL_VALUE}, None,
                               fail_reasons=["Transformation error: " + str(e)],
                               transformation_errors=[str(e)])


WINDOW_DAYS = 365


def parse_time(value):
    s = text(value)
    if len(s) < 19:
        return None
    try:
        return datetime.fromisoformat(s[:19])
    except Exception:
        return None


def evaluate(records):
    now = datetime.utcnow()
    recent = []
    newest = None
    for r in records:
        if text(r.get("status")).lower() != "successful":
            continue
        t = parse_time(r.get("ended")) or parse_time(r.get("lastUpdatedTime"))
        if t is None:
            continue
        if newest is None or t > newest:
            newest = t
        if (now - t).days <= WINDOW_DAYS:
            recent.append(r)
    summary = {"restoreJobsReported": len(records), "successfulRestoresInWindow": len(recent),
               "windowDays": WINDOW_DAYS,
               "newestSuccessfulRestore": newest.isoformat() + "Z" if newest is not None else None}
    if len(recent) > 0:
        return True, summary, [str(len(recent)) + " successful Druva restores in the last " + str(WINDOW_DAYS) + " days"]
    return False, summary, ["No successful Druva restore in the last " + str(WINDOW_DAYS) + " days (" + str(len(records)) + " restore jobs reported)"]
