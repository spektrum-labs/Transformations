"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft Azure Payment HSM  |  Category: Encryption

Criterion: the organization has a provisioned Azure Payment HSM (Thales payShield 10K) in service.

Data source: getPaymentHsms --
GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.HardwareSecurityModules/dedicatedHSMs?api-version=2021-11-30
(Payment HSMs are dedicatedHSMs resources with a payShield10K_* SKU,
https://learn.microsoft.com/en-us/azure/payment-hsm/quickstart-cli ; Azure RBAC Reader on the resource group).
Returns {value: [DedicatedHsm], nextLink}.

  confirmedLicensePurchased = at least one resource with sku.name starting payShield10K and
  properties.provisioningState == "Succeeded".

Returns paymentHsmCount and provisionedPaymentHsmCount. SafeNet Dedicated HSMs in the same resource group are not
counted. A valid list with no payment HSM is a measured false. What ARM cannot show: LMK, key and PCI settings,
which live in payShield Manager. Fails closed: an error body, no value list, or a paged list returns None.
"""
import json
from datetime import datetime

KEY = "confirmedLicensePurchased"
VENDOR = "Microsoft Azure Payment HSM"
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


def is_payment_hsm(resource):
    sku = resource.get("sku") if isinstance(resource.get("sku"), dict) else {}
    return str(sku.get("name") or "").lower().startswith("payshield10k")


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Azure Resource Manager returned an error for the dedicated HSM list", validation)
        resources = data.get("value") if isinstance(data, dict) else None
        if not isinstance(resources, list) or data.get("nextLink"):
            return not_measured("No complete dedicated HSM list was returned", validation)
        payment = [r for r in resources if isinstance(r, dict) and r.get("id") and is_payment_hsm(r)]
        provisioned = 0
        for resource in payment:
            props = resource.get("properties") if isinstance(resource.get("properties"), dict) else {}
            if props.get("provisioningState") == "Succeeded":
                provisioned = provisioned + 1
        result = {KEY: provisioned > 0, "paymentHsmCount": len(payment), "provisionedPaymentHsmCount": provisioned}
        line = str(provisioned) + " of " + str(len(payment)) + " payment HSMs are provisioned"
        if provisioned > 0:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=result)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=result,
                               recommendations=["Confirm the Payment HSM resource group and that its payShield HSMs are provisioned"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
