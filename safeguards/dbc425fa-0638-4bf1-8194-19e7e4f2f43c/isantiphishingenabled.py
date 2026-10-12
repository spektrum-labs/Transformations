"""
Transformation: isAntiPhishingEnabled
Vendor: Email Security Provider
Category: Email Security

Evaluates Mail Policies to check for Anti-Phishing settings including
domain spoofing and employee name spoofing detection.

Measured: a policy list that was read. isEmailSecurityEnabled is true when it holds a policy;
isAntiPhishingEnabled is true when a policy carries the spoofing settings and none is off, and
false when a policy was read with a spoofing setting off or none carries the settings.

Not measured (both keys None and dataCollection error, so Token-Service shows Not evaluated, never
Failed): a refusal or error body, a body that is not JSON or not a policy list, an empty policy
list, a failed input validation, a list still carrying nextPageToken in which no spoofing setting is
off yet (more pages could hold one), and this transform's own exception.
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


def unmeasured(reason, validation, summary=None):
    """The read could not answer: every key None and a dataCollection error, so it shows as Not evaluated."""
    return create_response(
        result={"isEmailSecurityEnabled": None, "isAntiPhishingEnabled": None},
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        input_summary=summary
    )


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

        policies = data.get("policies")
        if not isinstance(policies, list):
            return unmeasured("No policies list in the response: the mail policy read cannot be shown to have run",
                              validation)
        if not [p for p in policies if isinstance(p, dict)]:
            return unmeasured("No mail policies were returned: an empty list cannot be told apart from a read "
                              "that returned nothing", validation)
        truncated = is_truncated(data)

        matching_values = []
        for policy in policies:
            if isinstance(policy, dict) and "setting" in policy:
                setting = policy.get("setting", {})
                value = setting.get("value", {}) if isinstance(setting, dict) else {}
                if isinstance(value, dict):
                    filtered = {key: value[key] for key in value if key in filter_attributes}
                    if filtered:
                        matching_values.append(filtered)

        isAntiPhishingEnabled = False
        isEmailSecurityEnabled = False

        if len(policies) > 0:
            isEmailSecurityEnabled = True
            pass_reasons.append(f"Email security policies configured: {len(policies)} policies")

        # If any of the matching values are None or False, set isAntiPhishingEnabled to False
        if len(matching_values) > 0:
            isAntiPhishingEnabled = True
            for mv in matching_values:
                for key, value in mv.items():
                    if value is None or not bool(value):
                        isAntiPhishingEnabled = False
                        break
                if not isAntiPhishingEnabled:
                    break

        if truncated and (len(matching_values) == 0 or isAntiPhishingEnabled):
            # More pages exist. A spoofing setting that is off already decides False; nothing read so far can
            # prove True, or prove that no policy carries the settings.
            return unmeasured("The policy list was truncated (nextPageToken present) before every policy was "
                              "read; anti-phishing not evaluated across all policies", validation,
                              {"totalPolicies": len(policies), "antiPhishingPolicies": len(matching_values)})

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
                "antiPhishingPolicies": len(matching_values)
            }
        )

    except Exception as e:
        return create_response(
            result={"isEmailSecurityEnabled": None, "isAntiPhishingEnabled": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
