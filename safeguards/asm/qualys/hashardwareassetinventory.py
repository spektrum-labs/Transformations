"""
Transformation: hasHardwareAssetInventory
Vendor: Qualys  |  Category: Attack Surface Management
Evaluates: Whether the Qualys host list (HOST_LIST_OUTPUT) holds any host.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "hasHardwareAssetInventory", "vendor": "Qualys", "category": "Attack Surface Management"}
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


def evaluate(data):
    """Hosts in the Qualys host list (HOST_LIST_OUTPUT), the reply getHostList returns.

    It used to read data['count'], a key that reply never has, so it answered False for every estate.
    """
    try:
        output = data.get('HOST_LIST_OUTPUT') if isinstance(data, dict) else None
        response = output.get('RESPONSE') if isinstance(output, dict) else None
        if not isinstance(response, dict):
            return {"hasHardwareAssetInventory": None, "errorCode": "not_measured",
                    "notMeasured": "Qualys returned no host list, so the hardware asset inventory could not be checked."}
        host_list = response.get('HOST_LIST')
        if host_list is not None and not isinstance(host_list, dict):
            host_list = {'HOST': [host_list]}  # present but not a record: unreadable, never "no hosts"
        hosts = host_list.get('HOST', []) if isinstance(host_list, dict) else []
        if isinstance(hosts, dict):
            hosts = [hosts]
        if not isinstance(hosts, list):
            hosts = [hosts]
        records = [h for h in hosts if isinstance(h, dict)]
        if not hosts:
            # Qualys omits HOST_LIST when it inventories nothing: no host is a measured "no inventory". A False
            # fails, so it cannot pass unearned; externalAssetInventoryCount leaves the same reply ungraded
            # because its 0 would pass an inclusive "greaterThan 0".
            return {"hasHardwareAssetInventory": False, "hardwareAssetCount": 0}
        if not records:
            return {"hasHardwareAssetInventory": None, "errorCode": "not_measured",
                    "notMeasured": "The Qualys host list could not be read, so the hardware asset inventory could not be checked."}
        # A truncated list (WARNING 1980) still holds these hosts, and one host is all True claims, so it stays True.
        return {"hasHardwareAssetInventory": True, "hardwareAssetCount": len(records)}
    except Exception:
        return {"hasHardwareAssetInventory": None, "error": "unreadable value in the Qualys reply"}


def transform(input):
    criteriaKey = "hasHardwareAssetInventory"
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
            return not_measured(criteriaKey, "The Qualys response failed validation, so the hardware asset inventory could not be checked.",
                                "not_measured", validation=validation)
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], eval_result["errorCode"], validation=validation)
        result_value = eval_result.get(criteriaKey)
        if not isinstance(result_value, bool):
            return not_measured(criteriaKey, "The Qualys response could not be read, so the hardware asset inventory could not be checked.",
                                "not_measured", validation=validation,
                                transformation_errors=[eval_result.get("error", "no value")])
        count = eval_result["hardwareAssetCount"]
        summary = {criteriaKey: result_value, "hardwareAssetCount": count}
        if result_value:
            return create_response(result=summary, validation=validation, input_summary=summary,
                                   pass_reasons=["Qualys lists " + str(count) + " hosts in its asset inventory."])
        return create_response(result=summary, validation=validation, input_summary=summary,
                               fail_reasons=["Qualys lists no hosts in its asset inventory."],
                               recommendations=["Add the hosts in scope to Qualys asset inventory."])
    except Exception:
        return not_measured(criteriaKey, "The Qualys response could not be read, so the hardware asset inventory could not be checked.",
                            "not_measured", validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=["unreadable value in the Qualys reply"])
