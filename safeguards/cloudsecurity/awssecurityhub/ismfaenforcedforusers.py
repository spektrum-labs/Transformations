"""
Transformation: isMFAEnforcedForUsers
Vendor: AWS Security Hub  |  Category: Cloud Security

Evaluates AWS Security Hub control(s) IAM.5 from the getSecurityHubComplianceAWS
findings. A control passes unless it has an active FAILED finding; the criterion passes
only when every checked control that is present is passing. Fails closed if no active
finding for these controls is returned.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isMFAEnforcedForUsers"
CONTROL_IDS = ['IAM.5']
TRANSFORM_ID = "ismfaenforcedforusers"


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


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (errors or []) else "success", "errors": errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (errors or []) else "success", "errors": errors or [], "inputSummary": {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORM_ID, "vendor": "AWS Security Hub", "category": "Cloud Security"},
        },
    }


def transform(input):
    try:
        findings = extract_findings(input)
        statuses = []
        failed_controls = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            comp = f.get("Compliance") or {}
            if comp.get("SecurityControlId") not in CONTROL_IDS:
                continue
            status = str(comp.get("Status") or "").upper()
            if status in ("PASSED", "FAILED"):
                statuses.append(status)
                if status == "FAILED":
                    cid = comp.get("SecurityControlId")
                    if cid not in failed_controls:
                        failed_controls.append(cid)
        if not statuses:
            return build_response({CRITERIA_KEY: False},
                                  fail_reasons=["No active Security Hub findings for control(s): " + ", ".join(CONTROL_IDS)])
        passed = "FAILED" not in statuses
        if passed:
            return build_response({CRITERIA_KEY: True},
                                  pass_reasons=["All checked controls passing: " + ", ".join(CONTROL_IDS)])
        return build_response({CRITERIA_KEY: False},
                              fail_reasons=["Failing control(s): " + ", ".join(failed_controls)])
    except Exception as error:
        return build_response({CRITERIA_KEY: False}, errors=[str(error)])
