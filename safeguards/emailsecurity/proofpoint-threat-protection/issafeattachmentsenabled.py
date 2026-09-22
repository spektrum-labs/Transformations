"""
Transformation: isSafeAttachmentsEnabled
Vendor: Proofpoint (Threat Protection / Core Email Protection)  |  Category: Email Security
Evaluates: Attachment Defense is scanning inbound attachments, proven by the protected share of attachment-bearing messages.
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
                         "transformationId": "isSafeAttachmentsEnabled", "vendor": "Proofpoint", "category": "Email Security"},
        },
    }
def find_breakdown(rows, name):
    for r in rows:
        if isinstance(r, dict) and str(r.get("breakdownName", "")).lower() == name:
            return r
    return None


def evaluate(data):
    if not isinstance(data, dict):
        return {"isSafeAttachmentsEnabled": False, "reason": "Unexpected response type"}
    rows = data.get("statsByBreakdownValue")
    if not isinstance(rows, list):
        return {"isSafeAttachmentsEnabled": False, "reason": "messages-protected report returned no breakdown"}
    att = find_breakdown(rows, "attachment")
    if not att:
        return {"isSafeAttachmentsEnabled": False, "reason": "No attachment breakdown present in messages-protected report"}
    total = att.get("breakdownMessagesTotal") or 0
    protected = att.get("breakdownProtectedMessagesTotal") or 0
    exposed = att.get("potentiallyExposedMessages") or 0
    if total <= 0:
        return {"isSafeAttachmentsEnabled": False, "reason": "No attachment-bearing messages observed in the window"}
    rate = round((protected * 100.0) / total, 2)
    return {"isSafeAttachmentsEnabled": rate >= 95.0,
            "attachmentMessagesTotal": total, "attachmentMessagesProtected": protected,
            "potentiallyExposedMessages": exposed, "attachmentProtectionRatePct": rate}


def transform(input):
    key = "isSafeAttachmentsEnabled"
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
            pr = [f"Attachment Defense protected {extra.get('attachmentMessagesProtected')} of {extra.get('attachmentMessagesTotal')} attachment-bearing messages ({extra.get('attachmentProtectionRatePct')}%), {extra.get('potentiallyExposedMessages')} potentially exposed"]
            fr = []
        else:
            pr = []
            fr = [res.get("reason", "Attachment protection rate is below the 95% threshold")]
        return create_response({key: value, **extra}, validation, pr, fr,
                               [] if value else ["Enable Attachment Defense sandboxing for inbound mail"],
                               {key: value, **extra})
    except Exception as e:
        return create_response({key: False}, None, [], ["Transformation error"], [], {}, [str(e)])
