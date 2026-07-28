"""
Transformation: compliancePercentage
Vendor: AWS Security Hub  |  Category: Cloud Security

Control-level compliance score (matches AWS Security Hub's own methodology): findings are
deduplicated by SecurityControlId, a control passes unless any active finding for it is
FAILED, and the score is passing_controls / total_controls. Sets both compliancePercentage
and CIScompliancePercentage from the findings provided (the method determines the standard).
"""

import json
from datetime import datetime

TRANSFORM_ID = "compliancepercentage"


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
        control_failed = {}
        for f in findings:
            if not isinstance(f, dict):
                continue
            comp = f.get("Compliance") or {}
            cid = comp.get("SecurityControlId")
            status = str(comp.get("Status") or "").upper()
            if not cid or status not in ("PASSED", "FAILED"):
                continue
            if cid not in control_failed:
                control_failed[cid] = False
            if status == "FAILED":
                control_failed[cid] = True
        total = len(control_failed)
        passing = 0
        for cid in control_failed:
            if not control_failed[cid]:
                passing += 1
        percentage = int(round(100 * passing / total)) if total > 0 else 0
        result = {
            "compliancePercentage": percentage,
            "CIScompliancePercentage": percentage,
            "passingControls": passing,
            "totalControls": total,
        }
        return build_response(result,
                              pass_reasons=[str(percentage) + "% of controls passing (" + str(passing) + "/" + str(total) + ")"])
    except Exception as error:
        return build_response({"compliancePercentage": 0, "CIScompliancePercentage": 0}, errors=[str(error)])
