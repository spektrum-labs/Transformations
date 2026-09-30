"""
Transformation: isLocalAuthDisabled
Vendor: Microsoft Foundry  |  Category: Artificial Intelligence

Criterion: every Foundry resource has key-based (local) authentication disabled, so callers must use Microsoft Entra ID.

Data source: getFoundryAccounts --
GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.CognitiveServices/accounts?api-version=2024-10-01
(https://learn.microsoft.com/en-us/rest/api/aiservices/accountmanagement/accounts/list?view=rest-aiservices-accountmanagement-2024-10-01,
Azure RBAC Reader on the subscription). Only accounts of kind AIServices (Foundry resources) are evaluated;
other Cognitive Services kinds in the subscription are ignored. Returns {value: [Account], nextLink}.

  isLocalAuthDisabled = the list holds at least one of the Foundry resources AND every one has properties.disableLocalAuth == true.

Returns resourceCount and localAuthDisabledCount. Fails closed: an error body, no value list, a paged list (nextLink present),
zero resources, or a resource missing the field returns None.
ARM omits unset properties; a resource without disableLocalAuth is read as false (keys allowed), never as true.
"""
import json
from datetime import datetime

KEY = "isLocalAuthDisabled"
VENDOR = "Microsoft Foundry"
CATEGORY = "Artificial Intelligence"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None}, validation=validation, api_errors=[reason], fail_reasons=[reason])


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value == int(value) and value >= 0:
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def is_error_body(data):
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors"):
        return True
    status = data.get("statusCode") or data.get("status_code") or data.get("status")
    if isinstance(status, int) and status >= 400:
        return True
    return False


def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        input = json.loads(input) if input.strip() else None
    return extract_input(input)


FIELD_PATH = ["properties", "disableLocalAuth"]
EXPECT = True
LABEL = "Foundry resources"
MISSING_AS = False
KINDS = ['AIServices']


def field(resource):
    node = resource
    for part in FIELD_PATH:
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Azure Resource Manager returned an error for the " + LABEL + " list", validation)
        resources = data.get("value") if isinstance(data, dict) else None
        if not isinstance(resources, list) or data.get("nextLink"):
            return not_measured("No complete " + LABEL + " list was returned", validation)
        items = [r for r in resources if isinstance(r, dict) and r.get("id") and (not KINDS or r.get("kind") in KINDS)]
        if not items:
            return not_measured("The subscription has no " + LABEL + " to evaluate", validation)
        matching = 0
        failing = []
        for resource in items:
            value = field(resource)
            if value is None:
                value = MISSING_AS
            if value is None:
                return not_measured(LABEL + " " + str(resource.get("name")) + " does not report " + ".".join(FIELD_PATH),
                                    validation)
            if value == EXPECT:
                matching = matching + 1
            else:
                failing.append(str(resource.get("name") or resource.get("id")))
        total = len(items)
        result = {KEY: matching == total, "resourceCount": total, "localAuthDisabledCount": matching}
        line = str(matching) + " of " + str(total) + " " + LABEL + " have " + ".".join(FIELD_PATH) + " = " + str(EXPECT)
        if matching == total:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=result)
        return create_response(result=result, validation=validation, input_summary=result,
                               fail_reasons=[line + "; not set on: " + ", ".join(failing)],
                               recommendations=["Set disableLocalAuth to true on every Foundry resource and move callers to Microsoft Entra ID"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
