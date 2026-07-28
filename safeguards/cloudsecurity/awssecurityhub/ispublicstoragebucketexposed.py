import json
from datetime import datetime


def extract_findings(input_data):
    data = input_data
    if isinstance(data, str):
        data = json.loads(data)
    elif isinstance(data, bytes):
        data = json.loads(data.decode("utf-8"))
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = data["data"]
    for _ in range(4):
        if not isinstance(data, dict):
            break
        nxt = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), (dict, list)):
                nxt = data[key]
                break
        if nxt is None:
            break
        data = nxt
    if isinstance(data, dict) and "Findings" in data:
        return data["Findings"]
    if isinstance(data, list):
        return data
    return []


def build_response(result, transform_id, pass_reasons=None, fail_reasons=None, errors=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (errors or []) else "success", "errors": errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (errors or []) else "success", "errors": errors or [], "inputSummary": {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": "AWS Security Hub", "category": "Cloud Security"},
        },
    }


def control_status_map(findings, control_ids):
    statuses = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        comp = f.get("Compliance") or {}
        cid = comp.get("SecurityControlId")
        if cid not in control_ids:
            continue
        status = str(comp.get("Status") or "").upper()
        if status in ("PASSED", "FAILED"):
            prev = statuses.get(cid)
            statuses[cid] = "FAILED" if (status == "FAILED" or prev == "FAILED") else "PASSED"
    return statuses


CRITERIA_KEY = "isPublicStorageBucketExposed"
CONTROL_IDS = ["S3.1", "S3.2", "S3.3", "S3.8"]
TRANSFORM_ID = "ispublicstoragebucketexposed"


def transform(input):
    try:
        findings = extract_findings(input)
        statuses = control_status_map(findings, CONTROL_IDS)
        failed = [cid for cid, st in statuses.items() if st == "FAILED"]
        exposed = len(failed) > 0
        return build_response({CRITERIA_KEY: exposed}, TRANSFORM_ID,
                              fail_reasons=["Public S3 exposure: " + ", ".join(failed)] if exposed else [],
                              pass_reasons=[] if exposed else ["No public S3 bucket exposure detected"])
    except Exception as error:
        return build_response({CRITERIA_KEY: True}, TRANSFORM_ID, errors=[str(error)])
