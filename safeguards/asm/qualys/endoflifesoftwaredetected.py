"""
Transformation: endOfLifeSoftwareDetected
Vendor: Qualys  |  Category: Attack Surface Management
Evaluates: Whether end-of-life software is present in the environment.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "endOfLifeSoftwareDetected", "vendor": "Qualys", "category": "Attack Surface Management"}
        }
    }


# The read is ours, so a gap in it is ours to fix: the customer is told so, and errorCode routes it to engineering.
NOT_OURS_TO_ASK = "Nothing is needed from you; this is on Spektrum's side."


def not_measured(criteria_key, reason, error_code, validation=None, transformation_errors=None, findings=None,
                 recommendations=(NOT_OURS_TO_ASK,)):
    """criteria_key None plus a coded dataCollection error, so the evaluator records Not evaluated."""
    response = create_response(
        result={criteria_key: None}, validation=validation,
        api_errors=[reason], fail_reasons=[reason], transformation_errors=transformation_errors,
        additional_findings=findings, recommendations=list(recommendations))
    response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response


# --- Qualys refusal: byte-identical in every Qualys transform (a test compares the copies) -------------------
VERIFY_ACCESS = "Verify the Qualys API credentials and the permissions of the Qualys user Spektrum connects as."
# Qualys's login and account refusals: 2000 Bad Login/Password, 2002 account inactive, 2003 registration incomplete.
QUALYS_LOGIN_CODES = {'2000', '2002', '2003'}


def vendor_refusal(data):
    """The reason when Qualys, or the relay in front of it, refused our credentials; None for any other reply.

    A refusal is the customer's to fix, so it is coded vendor_refusal with text the diagnosis reads as an auth
    failure. Every other error reply (a parameter Qualys rejected, a body we cannot read) stays ours.
    """
    if not isinstance(data, dict):
        return None
    simple = data.get('SIMPLE_RETURN')
    reply = simple.get('RESPONSE') if isinstance(simple, dict) else None
    if isinstance(reply, dict) and str(reply.get('CODE', '')).strip() in QUALYS_LOGIN_CODES:
        return ("Qualys refused the API login (authentication failed, Qualys code %s), so this check could not "
                "be evaluated." % str(reply.get('CODE')).strip())
    status = str(data.get('statusCode', data.get('status_code', ''))).strip()
    message = str(data.get('message', '')).upper()
    for code in ('401', '403'):
        if status == code or ('HTTP ' + code) in message:
            return "Qualys refused Spektrum's request (HTTP %s), so this check could not be evaluated." % code
    return None
# --- end Qualys refusal -----------------------------------------------------------------------------------------


# Qualys CSAM lifecycle stages. Only a stage named here as current can answer "no end-of-life software".
# A stage is split on "/" and "," and each part matched whole, so "EOL/EOS" is end of life and "Not EOL" is unread.
END_OF_LIFE_TOKENS = ('eol', 'eos', 'obsolete', 'end of life', 'end-of-life', 'end of support', 'end-of-support')
CURRENT_STAGES = ('ga', 'general availability', 'pre-ga', 'beta')


def lifecycle_kind(lifecycle):
    """'eol', 'current' or 'unread' for one software lifecycle (a stage string or {"stage": ...})."""
    stage = lifecycle.get('stage') if isinstance(lifecycle, dict) else lifecycle
    if not isinstance(stage, str):
        return 'unread'
    parts = [part.strip() for part in stage.lower().replace(',', '/').split('/') if part.strip()]
    if any(part in END_OF_LIFE_TOKENS for part in parts):
        return 'eol'
    if parts and all(part in CURRENT_STAGES for part in parts):
        return 'current'
    return 'unread'


def evaluate(data):
    """End-of-life software, when the reply carries the asset inventory (assetListData).

    getHostList returns the Qualys host list, which has no assetListData key, so this used to answer
    "no end-of-life software" for every estate. Without the key nothing was measured.
    """
    try:
        asset_list = data.get('assetListData') if isinstance(data, dict) else None
        assets = asset_list.get('asset') if isinstance(asset_list, dict) else None
        if isinstance(assets, dict):
            assets = [assets]
        if not isinstance(assets, list) or not assets:
            return {"endOfLifeSoftwareDetected": None,
                    "notMeasured": "Spektrum's Qualys read does not yet include installed software, so "
                                   "end-of-life software could not be checked."}
        kinds = {}
        assets_read = 0
        for asset in assets:
            software_list = asset.get('softwareListData') if isinstance(asset, dict) else None
            software = software_list.get('software') if isinstance(software_list, dict) else None
            if isinstance(software, dict):
                software = [software]
            if not isinstance(software, list) or not software:
                continue
            assets_read += 1
            for sw in software:
                kind = lifecycle_kind(sw.get('lifecycle') if isinstance(sw, dict) else None)
                kinds[kind] = kinds.get(kind, 0) + 1
        unread = kinds.get('unread', 0)
        if kinds.get('eol'):
            return {"endOfLifeSoftwareDetected": True, "assetsScanned": assets_read}
        if not kinds:
            # Assets with no software list prove nothing about end-of-life software.
            return {"endOfLifeSoftwareDetected": None,
                    "notMeasured": "Spektrum's Qualys read does not yet include installed software, so "
                                   "end-of-life software could not be checked."}
        if unread:
            # Software whose stage is Unknown or unrecognised is not proof it is current.
            return {"endOfLifeSoftwareDetected": None, "unreadLifecycles": unread,
                    "notMeasured": "Qualys reported software whose lifecycle Spektrum could not read, so "
                                   "end-of-life software could not be checked."}
        return {"endOfLifeSoftwareDetected": False, "assetsScanned": assets_read}
    except Exception:
        return {"endOfLifeSoftwareDetected": None, "error": "unreadable value in the Qualys reply"}


def transform(input):
    criteriaKey = "endOfLifeSoftwareDetected"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        refusal = vendor_refusal(data)
        if refusal:
            return not_measured(criteriaKey, refusal, "vendor_refusal", validation=validation,
                                recommendations=(VERIFY_ACCESS,))
        if validation.get("status") == "failed":
            return not_measured(criteriaKey, "The Qualys response failed validation, so end-of-life software "
                                "could not be checked.", "not_measured", validation=validation)
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], "not_measured", validation=validation)
        result_value = eval_result.get(criteriaKey)
        if not isinstance(result_value, bool):
            return not_measured(criteriaKey, "The Qualys response could not be read, so end-of-life software "
                                "could not be checked.", "not_measured", validation=validation,
                                transformation_errors=[eval_result.get("error", "no value")])
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey}
        reason = ("End-of-life software is installed on assets Qualys inventories." if result_value
                  else "No end-of-life software on the " + str(eval_result["assetsScanned"]) + " assets whose software Qualys lists.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            additional_findings=[reason],
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception:
        return not_measured(criteriaKey, "The Qualys response could not be read, so end-of-life software "
                            "could not be checked.", "not_measured",
                            validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=["unreadable value in the Qualys reply"])
