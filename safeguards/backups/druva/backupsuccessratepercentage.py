"""
Transformation: backupSuccessRatePercentage
Vendor: Druva (Data Security Cloud, Enterprise Workloads)  |  Category: Backups
Method: getBackupActivity -> POST /platform/reporting/v1/reports/ewBackupActivity
Evaluates: Percentage of jobs in the Druva Backup Activity report (last 24 hours, the report default) whose status is Successful. None when no jobs are reported.
Fails closed: a missing, error or unrecognised body returns None.
"""
import json
from datetime import datetime

CRITERIA_KEY = "backupSuccessRatePercentage"
FAIL_VALUE = None
RECOMMENDATION = "Investigate the Druva backup jobs that did not complete successfully."


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


def evaluate(records):
    ok = [r for r in records if text(r.get("status")).lower() == "successful"]
    summary = {"backupJobsReported": len(records), "backupJobsSuccessful": len(ok)}
    if len(records) == 0:
        return None, summary, ["Druva Backup Activity report returned no jobs in its window; rate not proven"]
    rate = round(len(ok) * 100.0 / len(records), 2)
    return rate, summary, [str(len(ok)) + " of " + str(len(records)) + " Druva backup jobs Successful (" + str(rate) + "%)"]
