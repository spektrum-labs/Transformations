"""
Transformation: isDataClassificationEnabled
Vendor: Microsoft Purview Information Protection  |  Category: Data Security

Criterion: data classification is in use: the tenant publishes at least one active sensitivity label.

Data source: getSensitivityLabels --
GET https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels
(https://learn.microsoft.com/en-us/graph/api/security-informationprotection-list-sensitivitylabels?view=graph-rest-beta,
application permission InformationProtectionPolicy.Read.All; beta only, global cloud only). Label properties
(https://learn.microsoft.com/en-us/graph/api/resources/security-sensitivitylabel?view=graph-rest-beta):
isActive / isEnabled, hasProtection (encryption or do-not-forward configured).
A label counts as active when isActive or isEnabled is true.
Fails closed: an error body, no value list, or a paged list (@odata.nextLink) returns None.
Returns activeLabelCount. A tenant with no active label is a measured false.
"""
import json
from datetime import datetime

KEY = "isDataClassificationEnabled"
VENDOR = "Microsoft Purview Information Protection"
CATEGORY = "Data Security"


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


def label_counts(data):
    if not isinstance(data, dict):
        return None
    labels = data.get("value")
    if not isinstance(labels, list) or data.get("@odata.nextLink"):
        return None
    active = 0
    protected = 0
    for label in labels:
        if not isinstance(label, dict) or not label.get("id"):
            continue
        if label.get("isActive") is True or label.get("isEnabled") is True:
            active = active + 1
            if label.get("hasProtection") is True:
                protected = protected + 1
    return active, protected, len(labels)

def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Microsoft Graph returned an error for sensitivityLabels", validation)
        counts = label_counts(data)
        if counts is None:
            return not_measured("No complete sensitivityLabels list was returned", validation)
        active = counts[0]
        protected = counts[1]
        summary = {"activeLabelCount": active, "protectedLabelCount": protected, "listedLabelCount": counts[2]}
        result = {KEY: active > 0, "activeLabelCount": active}
        line = str(active) + " active sensitivity labels are published"
        if active > 0:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=summary)
        return create_response(result=result, validation=validation, fail_reasons=[line], input_summary=summary,
                               recommendations=["Create and publish sensitivity labels in Microsoft Purview"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
