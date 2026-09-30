"""
Transformation: isLocalAuthDisabled
Vendor: Microsoft Foundry  |  Category: Artificial Intelligence

Criterion: every Foundry (AIServices) resource has key-based local authentication disabled. An omitted disableLocalAuth counts as not disabled.

Data source: getFoundrySummary --
POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01
body {"query": "resources | where type =~ 'microsoft.cognitiveservices/accounts' and kind =~ 'AIServices' | summarize subscriptionCount = dcount(subscriptionId), resourceCount = count(), localAuthDisabledCount = countif(tobool(properties.disableLocalAuth) == true), publicAccessDisabledCount = countif(tostring(properties.publicNetworkAccess) =~ 'Disabled')"}
(https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2022-10-01).
Signed in with the Spektrum One-Click certificate app (management.azure.com scope). With no subscriptions in the
body Resource Graph searches every subscription the app's service principal can read (Azure RBAC Reader), and the
summarize returns exactly one row of counts, so there is no paging. subscriptionCount (dcount of subscriptionId) is
returned with every result: Resource Graph only sees subscriptions where the app holds Reader, so a pass covers exactly
that many subscriptions and no more. Assign Reader at the root management group to cover the whole tenant.

Resource Graph answers an app with no Reader role anywhere with ZERO rows counted, not an error. Zero Foundry resources
therefore means "not measured" (None), never compliant and never a measured false.
Fails closed: an error body, a body without totalRecords/data, resultTruncated "true", a row without integer
counts, a count above the total, or zero Foundry resources returns None.

  isLocalAuthDisabled = true when every one of them is counted in localAuthDisabledCount.
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


TOTAL_FIELD = "resourceCount"
COUNT_FIELD = "localAuthDisabledCount"
RULE = "all"
LABEL = "Foundry resources"
COUNT_FIELDS = ["resourceCount", "localAuthDisabledCount", "publicAccessDisabledCount", "subscriptionCount"]


def summary_row(data):
    if not isinstance(data, dict) or as_count(data.get("totalRecords")) is None:
        return None
    rows = data.get("data")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return None
    if str(data.get("resultTruncated") or "").lower() == "true":
        return None
    return rows[0]


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Azure Resource Graph returned an error", validation)
        row = summary_row(data)
        if row is None:
            return not_measured("No single Resource Graph summary row was returned", validation)
        counts = {}
        for name in COUNT_FIELDS:
            value = as_count(row.get(name))
            if value is None:
                return not_measured("The Resource Graph summary is missing " + name, validation)
            counts[name] = value
        total = counts[TOTAL_FIELD]
        matching = counts[COUNT_FIELD]
        if total <= 0:
            return not_measured("Resource Graph counts no " + LABEL + " the app can read; grant Reader or none exist",
                                validation)
        if matching > total:
            return not_measured("The Resource Graph summary is inconsistent", validation)
        passed = matching == total if RULE == "all" else matching > 0
        result = {KEY: passed}
        for name in COUNT_FIELDS:
            result[name] = counts[name]
        line = (str(matching) + " of " + str(total) + " " + LABEL + " counted in " + COUNT_FIELD + ", across "
                + str(counts["subscriptionCount"]) + " subscriptions the Spektrum app can read")
        if passed:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=counts)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=counts,
                               recommendations=["Set disableLocalAuth to true and move callers to Microsoft Entra ID"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
