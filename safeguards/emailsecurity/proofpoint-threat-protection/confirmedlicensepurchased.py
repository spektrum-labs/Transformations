"""
Transformation: confirmedLicensePurchased
Vendor: Proofpoint (Threat Protection / Core Email Protection)  |  Category: Email Security
Evaluates: An active, licensed Proofpoint tenant is processing inbound mail, proven by a
non-zero protected-message volume in the executive inbound-protection-overview report.
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
                         "transformationId": "confirmedLicensePurchased", "vendor": "Proofpoint",
                         "category": "Email Security"},
        },
    }


def evaluate(data):
    if not isinstance(data, dict):
        return {"confirmedLicensePurchased": False, "reason": "Unexpected response type"}
    pre = data.get("preDeliveryProtectedMessages")
    post = data.get("postDeliveryProtectedMessages")
    overall = data.get("overallInboundProtection")
    if pre is None and post is None and overall is None:
        return {"confirmedLicensePurchased": False,
                "reason": "inbound-protection-overview did not return protection metrics"}
    total = (pre or 0) + (post or 0)
    return {"confirmedLicensePurchased": total > 0,
            "protectedMessages": total,
            "overallInboundProtectionPct": round((overall or 0) * 100, 2)}


def transform(input):
    key = "confirmedLicensePurchased"
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
            pr = [f"Proofpoint processed {extra.get('protectedMessages')} protected messages; tenant is licensed and active"]
            fr = []
        else:
            pr = []
            fr = [res.get("reason", "No protected-message volume returned")]
        return create_response({key: value, **extra}, validation, pr, fr,
                               [] if value else ["Confirm the Proofpoint subscription is active for this cluster"],
                               {key: value, **extra})
    except Exception as e:
        return create_response({key: False}, None, [], ["Transformation error"], [], {}, [str(e)])
