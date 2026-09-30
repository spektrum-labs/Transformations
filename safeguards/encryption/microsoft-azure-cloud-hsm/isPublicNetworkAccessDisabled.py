"""
Transformation: isPublicNetworkAccessDisabled
Vendor: Microsoft Azure Cloud HSM  |  Category: Encryption

Criterion: public network access is disabled on every Cloud HSM cluster.

Data source: getCloudHsmClusters --
GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.HardwareSecurityModules/cloudHsmClusters?api-version=2024-06-30-preview
(operation CloudHsmClusters_ListBySubscription; properties per
https://learn.microsoft.com/en-us/python/api/azure-mgmt-hardwaresecuritymodules/azure.mgmt.hardwaresecuritymodules.models.cloudhsmclusterproperties?view=azure-python ;
Azure RBAC Reader on the subscription). Returns {value: [CloudHsmCluster], nextLink}.

  isPublicNetworkAccessDisabled = the list holds at least one of the Cloud HSM clusters AND every one has properties.publicNetworkAccess == "Disabled".

Returns resourceCount and publicAccessDisabledCount. Fails closed: an error body, no value list, a paged list (nextLink present),
zero resources, or a resource missing the field returns None.
"""
import json
from datetime import datetime

KEY = "isPublicNetworkAccessDisabled"
VENDOR = "Microsoft Azure Cloud HSM"
CATEGORY = "Encryption"


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


FIELD_PATH = ["properties", "publicNetworkAccess"]
EXPECT = 'Disabled'
LABEL = "Cloud HSM clusters"


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
        items = [r for r in resources if isinstance(r, dict) and r.get("id")]
        if not items:
            return not_measured("The subscription has no " + LABEL + " to evaluate", validation)
        matching = 0
        failing = []
        for resource in items:
            value = field(resource)
            if value is None:
                return not_measured(LABEL + " " + str(resource.get("name")) + " does not report " + ".".join(FIELD_PATH),
                                    validation)
            if value == EXPECT:
                matching = matching + 1
            else:
                failing.append(str(resource.get("name") or resource.get("id")))
        total = len(items)
        result = {KEY: matching == total, "resourceCount": total, "publicAccessDisabledCount": matching}
        line = str(matching) + " of " + str(total) + " " + LABEL + " have " + ".".join(FIELD_PATH) + " = " + str(EXPECT)
        if matching == total:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=result)
        return create_response(result=result, validation=validation, input_summary=result,
                               fail_reasons=[line + "; not set on: " + ", ".join(failing)],
                               recommendations=["Reach Cloud HSM clusters only through private endpoints (publicNetworkAccess Disabled)"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
