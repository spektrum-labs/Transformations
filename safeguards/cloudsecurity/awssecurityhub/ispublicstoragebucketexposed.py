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
    # None, not [], when the body carries no findings collection: `[]` would read as "AWS
    # returned no findings", and every verdict in this file rests on telling that apart
    # from "this body was never a findings response". Only an explicit `Findings` list is a
    # proven result set, so `{"Findings": []}` is a real zero and `{}` is not.
    if isinstance(data, dict) and isinstance(data.get("Findings"), list):
        return data["Findings"]
    if isinstance(data, list) and data:
        return data
    return None


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
        # FAIL CLOSED ON A BODY THAT IS NOT A FINDINGS RESPONSE. The shape read is Security
        # Hub GetFindings (POST /findings), whose response is
        # {"Findings": [AwsSecurityFinding, ...], "NextToken": "..."}. An AWS error is an
        # object carrying `__type`/`message` and no `Findings`; so is a 401/403 envelope, and
        # so is a payload about anything else. Before this, all of those came back as an
        # empty findings list and reported "No public S3 bucket exposure
        # detected" -- and this key is inverted, so the silent False was the rubber stamp.
        if findings is None:
            return build_response({CRITERIA_KEY: True}, TRANSFORM_ID,
                                  errors=["no Findings collection in the Security Hub GetFindings response: the findings "
                                          "query cannot be shown to have run, so the absence of a public-bucket "
                                          "finding is not evidence that no bucket is public"])
        statuses = control_status_map(findings, CONTROL_IDS)
        # A findings list that reports no status for any S3 public-access control is not an
        # all-clear either: those controls were not evaluated in what we were shown.
        if not statuses:
            return build_response({CRITERIA_KEY: True}, TRANSFORM_ID,
                                  errors=["the Security Hub findings carry no status for any of "
                                          + ", ".join(CONTROL_IDS) + ": the public-access controls "
                                          "were not evaluated in what was returned, so no exposure "
                                          "verdict can be given"])
        failed = [cid for cid, st in statuses.items() if st == "FAILED"]
        exposed = len(failed) > 0
        return build_response({CRITERIA_KEY: exposed}, TRANSFORM_ID,
                              fail_reasons=["Public S3 exposure: " + ", ".join(failed)] if exposed else [],
                              pass_reasons=[] if exposed else ["No public S3 bucket exposure detected"])
    except Exception as error:
        return build_response({CRITERIA_KEY: True}, TRANSFORM_ID, errors=[str(error)])
