"""
Transformation: isAntiPhishingEnabled
Vendor: Email Security Provider
Category: Email Security

Evaluates Mail Policies to check for Anti-Phishing settings including
domain spoofing and employee name spoofing detection.

Google returns several gmail.spoofing_and_authentication policies for one org unit (SYSTEM defaults for
unlicensed and licensed entities, and any ADMIN override) and applies the one with the greatest
policyQuery.sortOrder; only that policy is judged per org unit or group. A policy of that setting type is
judged even when it reports neither spoofing setting, so an override in force that omits them reads Not
evaluated rather than letting the default it supersedes decide. A body without setting types is matched by
the spoofing settings a policy carries.

Measured: a policy list that was read. isEmailSecurityEnabled is true when it holds a policy;
isAntiPhishingEnabled is true when a policy in force carries both spoofing settings and none is off, and
false when a policy in force reports a spoofing setting off or a complete list carries no policy with the settings.
A spoofing setting a policy does not report at all is not off, it is unknown (None).

Not measured (both keys None and dataCollection error, so Token-Service shows Not evaluated, never
Failed): a refusal or error body, a body that is not JSON or not a policy list, an empty policy
list, a failed input validation, a policy that carries one spoofing setting but not the other (and none
reports one off), a list still carrying nextPageToken (or paginationTruncated), and this transform's own
exception. A truncated list is never judged, even when a setting read so far is off: a later page can hold
the only policy with the settings, or one with a greater sortOrder for the same org unit that supersedes
a policy read here.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isEmailSecurityEnabled', 'isAntiPhishingEnabled')


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isAntiPhishingEnabled",
                "vendor": "Email Security Provider",
                "category": "Email Security"
            }
        }
    }


def vendor_error(data):
    """Google's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if isinstance(data, str) and data.strip() == "":
        return "Empty response body"
    if not isinstance(data, dict):
        return None
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return str(value.get("message") or value.get("status") or value.get("code") or value)
        return "%s %s" % (value, data.get("message") or data.get("error_description") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return None


def is_truncated(body):
    """True when the list still carries nextPageToken or the paginator marked the read as cut short."""
    if not isinstance(body, dict):
        return False
    marker = body.get("paginationTruncated")
    return bool(str(body.get("nextPageToken") or "").strip()) or marker is True or str(marker).strip().lower() == "true"


def is_true(value):
    """Cloud Identity returns booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def as_order(value):
    """policyQuery.sortOrder as a number; None when unreadable. Integration-Service hands scalars over as strings."""
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def in_force(records):
    """Split matching policy records into the ones Google applies and the ones they supersede.

    For one setting on one org unit (or group) Google returns several policies: the SYSTEM default for
    entities without a Gmail licence, the SYSTEM default for licensed users, and any ADMIN override. It
    resolves them by precedence: the policy with the greatest policyQuery.sortOrder is the one in force
    (Policy API concepts, Max reducer), so only that one is judged. Equal sortOrders on one target, and a
    sortOrder that cannot be read, are all judged (fail closed). Returns (judged, superseded).
    """
    top = {}
    for rec in records:
        if rec["order"] is not None and (rec["orgUnit"] not in top or rec["order"] > top[rec["orgUnit"]]):
            top[rec["orgUnit"]] = rec["order"]
    judged = []
    superseded = []
    for rec in records:
        if rec["order"] is None or rec["orgUnit"] not in top or rec["order"] >= top[rec["orgUnit"]]:
            judged.append(rec)
        else:
            superseded.append(rec)
    return judged, superseded


def unmeasured(reason, validation, summary=None):
    """The read could not answer: every key None and a dataCollection error, so it shows as Not evaluated."""
    return create_response(
        result={"isEmailSecurityEnabled": None, "isAntiPhishingEnabled": None},
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        input_summary=summary
    )


def wrapper_truncated(input_data):
    """True when a wrapper level that extract_input strips carries a truncation marker. The paginator can put
    nextPageToken or paginationTruncated beside the wrapped body, where is_truncated(data) never sees it."""
    data = input_data
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = data["data"]
    for attempt in range(4):
        if not isinstance(data, dict):
            return False
        if is_truncated(data):
            return True
        inner = None
        for key in ["api_response", "response", "result", "apiResponse", "Output"]:
            if key in data and isinstance(data.get(key), dict):
                inner = data[key]
                break
        if inner is None:
            return False
        data = inner
    return False


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return unmeasured("Input validation failed", validation)

        error = vendor_error(data)
        if error is None and not isinstance(data, dict):
            error = "Response is not a policy list"
        if error is not None:
            return unmeasured(error, validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        filter_attributes = ["detectDomainNameSpoofing", "detectEmployeeNameSpoofing"]
        spoofing_setting = "gmail.spoofing_and_authentication"

        policies = data.get("policies")
        if not isinstance(policies, list):
            return unmeasured("No policies list in the response: the mail policy read cannot be shown to have run",
                              validation)
        if not [p for p in policies if isinstance(p, dict)]:
            return unmeasured("No mail policies were returned: an empty list cannot be told apart from a read "
                              "that returned nothing", validation)
        if is_truncated(data) or wrapper_truncated(input):
            # More pages exist. A later page could hold the only policy with the spoofing settings, or one with a
            # greater sortOrder that supersedes a policy read here, so nothing read so far decides the result.
            return unmeasured("The policy list was truncated (nextPageToken present) before every policy was "
                              "read; anti-phishing not evaluated across all policies", validation,
                              {"truncated": True})

        matching = []
        for policy in policies:
            if isinstance(policy, dict) and "setting" in policy:
                setting = policy.get("setting", {})
                value = setting.get("value", {}) if isinstance(setting, dict) else {}
                typed = isinstance(setting, dict) and str(setting.get("type", "")).endswith(spoofing_setting)
                if not isinstance(value, dict):
                    value = {}
                filtered = {key: value[key] for key in value if key in filter_attributes}
                # A spoofing policy is kept even when it reports neither setting, so an override in force that
                # omits them is judged (Not evaluated) instead of letting a superseded default decide. A body
                # without setting types is matched by the settings it carries.
                if typed or filtered:
                    query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
                    target = str(query.get("orgUnit") or "unknown")
                    if query.get("group"):
                        target = target + " " + str(query.get("group"))
                    matching.append({"orgUnit": target, "value": filtered,
                                     "order": as_order(query.get("sortOrder")),
                                     "policyType": str(policy.get("type") or "")})
        # Judge only the policy in force on each org unit or group; Google's own precedence decides which.
        matching, superseded = in_force(matching)
        matching_values = [rec["value"] for rec in matching]

        isAntiPhishingEnabled = False
        isEmailSecurityEnabled = False

        if len(policies) > 0:
            isEmailSecurityEnabled = True
            pass_reasons.append(f"Email security policies configured: {len(policies)} policies")

        # A spoofing setting a policy reports as off is a finding. One it does not report at all (missing or
        # null) leaves the policy unjudged, never off.
        any_off = False
        any_missing = False
        for mv in matching_values:
            for key in filter_attributes:
                if mv.get(key) is None:
                    any_missing = True
                elif not is_true(mv.get(key)):
                    any_off = True

        if any_off:
            # A setting that is off in a policy in force decides False, whatever else is unreported.
            isAntiPhishingEnabled = False
        elif len(matching_values) == 0:
            # A complete list in which no policy carries the settings is a proven negative.
            isAntiPhishingEnabled = False
        elif any_missing:
            return unmeasured("A policy carries a spoofing setting but not both domain and employee name spoofing "
                              "detection, so anti-phishing cannot be judged", validation,
                              {"totalPolicies": len(policies), "antiPhishingPolicies": len(matching_values)})
        else:
            isAntiPhishingEnabled = True

        if isAntiPhishingEnabled:
            pass_reasons.append("Anti-phishing protection enabled (domain/employee spoofing detection)")
        else:
            fail_reasons.append("Anti-phishing protection not fully enabled in policies")
            recommendations.append("Enable domain name spoofing and employee name spoofing detection")

        return create_response(
            result={
                "isEmailSecurityEnabled": isEmailSecurityEnabled,
                "isAntiPhishingEnabled": isAntiPhishingEnabled,
                "policyDetails": matching_values
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalPolicies": len(policies),
                "antiPhishingPolicies": len(matching_values),
                "supersededPolicies": len(superseded)
            }
        )

    except Exception as e:
        return create_response(
            result={"isEmailSecurityEnabled": None, "isAntiPhishingEnabled": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
