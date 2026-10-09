"""
Transformation: confirmedLicensePurchased
Vendor: Proofpoint (Threat Protection / Core Email Protection)  |  Category: Email Security
Evaluates: An active, licensed Proofpoint tenant is processing inbound mail, proven by a
non-zero protected-message volume in the executive inbound-protection-overview report.

Not evaluated (None, with a dataCollection error), never False: an unexpected, empty or error response, a missing
report section, no volume in the window, or an exception. False only when the report was read and shows the control
below its threshold (isSafeLinksEnabled, isSafeAttachmentsEnabled). This check cannot read False: zero volume in the window is "no evidence", so it reads Not evaluated.
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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors: carry the reason.
    if not api_errors and isinstance(result, dict) and "confirmedLicensePurchased" in result and result["confirmedLicensePurchased"] is None:
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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
        return {"confirmedLicensePurchased": None, "reason": "Unexpected response type"}
    pre = data.get("preDeliveryProtectedMessages")
    post = data.get("postDeliveryProtectedMessages")
    overall = data.get("overallInboundProtection")
    if pre is None and post is None and overall is None:
        return {"confirmedLicensePurchased": None,
                "reason": "inbound-protection-overview did not return protection metrics"}
    total = (pre or 0) + (post or 0)
    if total <= 0:
        return {"confirmedLicensePurchased": None, "protectedMessages": total,
                "reason": "No protected-message volume in the report window; not evaluated"}
    return {"confirmedLicensePurchased": True,
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
        value = res.get(key)
        extra = {k: v for k, v in res.items() if k != key and k != "reason"}
        if value:
            pr = [f"Proofpoint processed {extra.get('protectedMessages')} protected messages; tenant is licensed and active"]
            fr = []
        else:
            pr = []
            fr = [res.get("reason", "No protected-message volume returned")]
        return create_response({key: value, **extra}, validation, pr, fr,
                               [] if value is not False else ["Confirm the Proofpoint subscription is active for this cluster"],
                               {key: value, **extra})
    except Exception as e:
        return create_response({key: None}, None, [], ["Transformation error: " + str(e)], [], {}, [str(e)])
