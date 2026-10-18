"""
Transformation: confirmedLicensePurchased
Vendor: AWS Security Hub  |  Category: Cloud Security

True when the body shows Security Hub is subscribed: a subscription, SKU, licence or licences field,
an active / enabled flag, or a GetFindings list (AWS only answers GetFindings for a subscribed
account, so a findings list, even an empty one, shows the service is on). False when a body carries one
of those fields and shows no licence (an empty licences list, an inactive or disabled flag).

Not evaluated (None, dataCollection status "error"), never False: an error body (this integration's,
an HTTP one or an AWS one), an empty, non-JSON or unrecognised body (none of the fields above), a
subscription, SKU or licence field that is present but null or empty, an active or enabled field that is not
a real boolean or the text "true" or "false" (blank, an empty list or object, a number, "no", "disabled": it does
not clearly say whether a licence exists), and an exception. The reason text is fixed; the vendor's own error text is
never copied into the result.

The body may sit inside api_response, response, result, apiResponse or Output wrappers, to a depth of five.
When the findings list has a next-page token (NextToken, or nextToken, on the page or on a wrapper), the
subscription is still shown by the findings seen, but the findings count is not a total: findingsCount is None
and findingsCountAtLeast carries the number seen.
"""

import json
from datetime import datetime

CRITERIA_KEY = "confirmedLicensePurchased"
TRANSFORM_ID = "confirmedlicensepurchased"
VENDOR = "AWS Security Hub"
CATEGORY = "Cloud Security"
WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output"]
LICENSE_FIELDS = ["subscription", "sku", "license", "active", "enabled"]
SINGLE_FIELDS = ["subscription", "sku", "license"]
ERROR_PROBLEM = "The Security Hub call returned an error, so there is nothing to measure."
SHAPE_PROBLEM = "The response carries no subscription, licence or findings field, so there is nothing to measure."
RAISED_PROBLEM = "The Security Hub response could not be processed, so no verdict can be given."
UNCLEAR_FLAG_PROBLEM = ("The active or enabled field in the response is not a clear true or false, so it does not say "
                        "whether a licence exists.")
EMPTY_FIELD_PROBLEM = ("A subscription, SKU, licence or active/enabled field in the response is empty, so it does not say "
                       "whether a licence exists.")


def parse_body(value):
    """JSON text to an object. Text that is not JSON is None (nothing readable), never an exception."""
    try:
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
    except ValueError:
        return None
    return value


def is_error_body(data):
    """True for an error envelope: this integration's, an HTTP one or an AWS one."""
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors") or data.get("__type") or data.get("ErrorResponse"):
        return True
    if isinstance(data.get("Error"), dict) and data.get("Error"):
        return True
    for key in ["statusCode", "status_code", "httpStatus", "status"]:
        code = data.get(key)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return True
    return False


def page_token(data):
    """The next-page token of a findings page: NextToken, or nextToken in lower camel case. None when there is none."""
    if isinstance(data, dict):
        return data.get("NextToken") or data.get("nextToken")
    return None


def has_licence_field(data):
    """True when the dict carries a findings list, a licences list or one of the licence fields."""
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("Findings"), list) or isinstance(data.get("licenses"), list):
        return True
    for field in LICENSE_FIELDS:
        if field in data:
            return True
    return False


def empty_value(value):
    """True for a value that says nothing: null, an empty or blank string, an empty list or object."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def flag_state(flag):
    """True or False for a real boolean or the text "true" / "false" (any case, blanks trimmed); None for anything else."""
    if isinstance(flag, bool):
        return flag
    if isinstance(flag, str):
        text = flag.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    return None


def usable(value):
    """True for a value that shows something: not null, not an empty or blank string or collection, not false or zero."""
    return bool(value) and not empty_value(value)


def unwrap(input_data):
    """(body, next_token, problem): the object the licence fields are read from, its next-page token, or why there is none."""
    data = parse_body(input_data)
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = parse_body(data["data"])
    token = None
    for depth in range(5):
        if is_error_body(data):
            return None, None, ERROR_PROBLEM
        token = token or page_token(data)
        if not isinstance(data, dict) or has_licence_field(data):
            break
        nxt = None
        for key in WRAPPER_KEYS:
            if isinstance(data.get(key), (dict, list)):
                nxt = data[key]
                break
        if nxt is None:
            break
        data = nxt
    # The loop reads levels 0-4; the page it ends on (level 5 when five wrappers were opened) has its token read here.
    token = token or page_token(data)
    if is_error_body(data):
        return None, None, ERROR_PROBLEM
    if not isinstance(data, dict):
        return None, None, SHAPE_PROBLEM
    return data, token, None


def build_response(result, pass_reasons=None, fail_reasons=None, api_errors=None, transformation_errors=None):
    api_errors = api_errors or []
    transformation_errors = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if transformation_errors else "success",
                               "errors": transformation_errors, "inputSummary": {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORM_ID, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_evaluated(reason, transformation_errors=None):
    """No verdict: the criterion is None and dataCollection is an error, so the evaluator shows Not
    evaluated. The reason is fixed text; the vendor's own error text is never copied into it."""
    return build_response({CRITERIA_KEY: None}, fail_reasons=["Not evaluated: " + reason], api_errors=[reason],
                          transformation_errors=transformation_errors)


def transform(input):
    """
    Ensures a valid response is returned from Security Hub findings.

    Parameters:
        input (dict): The JSON data containing awssecurityhub API response

    Returns:
        dict: The standard response; transformedResponse carries the confirmedLicensePurchased result
    """
    try:
        body, next_token, problem = unwrap(input)
        if problem is not None:
            return not_evaluated(problem)

        recognised = isinstance(body.get("Findings"), list) or isinstance(body.get("licenses"), list)
        for field in LICENSE_FIELDS:
            if field in body:
                recognised = True
        if not recognised:
            return not_evaluated(SHAPE_PROBLEM)

        license_purchased = False
        license_details = {}

        # Check common license fields
        if usable(body.get("subscription")):
            license_purchased = True
            license_details["subscription"] = body["subscription"]
        elif usable(body.get("sku")):
            license_purchased = True
            license_details["sku"] = body["sku"]
        elif usable(body.get("license")):
            license_purchased = True
            license_details["license"] = body["license"]
        elif isinstance(body.get("licenses"), list) and len(body["licenses"]) > 0:
            license_purchased = True
            license_details["licenses"] = body["licenses"]
        elif "active" in body or "enabled" in body:
            state = flag_state(body.get("active") if "active" in body else body.get("enabled"))
            if state is None:
                return not_evaluated(UNCLEAR_FLAG_PROBLEM)
            license_purchased = state
            license_details["status"] = "active" if license_purchased else "inactive"
        # AWS Security Hub specific - check if findings exist (service is enabled)
        elif isinstance(body.get("Findings"), list):
            license_purchased = True  # If we can query findings, Security Hub is enabled
            license_details["status"] = "enabled"
            if next_token:
                # More pages exist: the number seen is a lower bound, never a total.
                license_details["findingsCount"] = None
                license_details["findingsCountAtLeast"] = len(body["Findings"])
            else:
                license_details["findingsCount"] = len(body["Findings"])
        else:
            # Nothing shows a licence. An empty licences list or a false flag says there is none; a subscription,
            # SKU or licence field that is null or empty says nothing, so it is not a "no".
            for field in SINGLE_FIELDS:
                if field in body and empty_value(body[field]):
                    return not_evaluated(EMPTY_FIELD_PROBLEM)

        result = {CRITERIA_KEY: license_purchased}
        for name in license_details:
            result[name] = license_details[name]
        if license_purchased:
            return build_response(result, pass_reasons=["Security Hub is subscribed"])
        return build_response(result, fail_reasons=["No Security Hub subscription or licence was found"])
    except Exception as error:
        return not_evaluated(RAISED_PROBLEM, transformation_errors=[str(error)[:200]])
