"""
Transformation: isAntiPhishingEnabled
Vendor: Proofpoint (Threat Protection / Core Email Protection)  |  Category: Email Security
Evaluates: Phishing, impostor (BEC) and TOAD messages are being actively classified and blocked, proven by non-zero threat-category volumes.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for key in ["api_response", "response", "result", "apiResponse", "rawResponse"]:
            if key in data and isinstance(data.get(key), dict):
                data = data[key]
                break
    return data, {"status": "unknown", "errors": [], "warnings": []}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": validation,
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isAntiPhishingEnabled", "vendor": "Proofpoint", "category": "Email Security"},
        },
    }


def find_category(cats, name):
    for c in cats:
        if isinstance(c, dict) and str(c.get("name", "")).lower() == name:
            return c.get("volume") or 0
    return 0


def evaluate(data):
    if not isinstance(data, dict):
        return {"isAntiPhishingEnabled": False, "reason": "Unexpected response type"}
    cats = data.get("threatCategories")
    if not isinstance(cats, list):
        return {"isAntiPhishingEnabled": False, "reason": "threat-categories report returned no categories"}
    phishing = find_category(cats, "phishing")
    bec = find_category(cats, "bec")
    toad = find_category(cats, "toad")
    detected = phishing + bec + toad
    return {"isAntiPhishingEnabled": detected > 0,
            "phishingVolume": phishing, "becVolume": bec, "toadVolume": toad,
            "totalVolume": data.get("totalVolume") or 0}


def transform(input):
    key = "isAntiPhishingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        res = evaluate(data)
        value = res.get(key, False)
        extra = {k: v for k, v in res.items() if k != key and k != "reason"}
        if value:
            pr = [f"Proofpoint classified {extra.get('phishingVolume')} phishing, {extra.get('becVolume')} BEC and {extra.get('toadVolume')} TOAD messages, confirming anti-phishing analysis is active"]
            fr = []
        else:
            pr = []
            fr = [res.get("reason", "No phishing, BEC or TOAD detections were reported")]
        return create_response({key: value, **extra}, validation, pr, fr,
                               [] if value else ["Verify impostor and phishing detection modules are enabled"],
                               {key: value, **extra})
    except Exception as e:
        return create_response({key: False}, None, [], ["Transformation error"], [], {}, [str(e)])
