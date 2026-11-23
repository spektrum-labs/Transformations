"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Google Workspace (Cloud Identity Policy API)
Category: Multifactor Authentication / Identity

Evidence: getPolicies
  GET https://cloudidentity.googleapis.com/v1beta1/policies  (paged: pageSize/pageToken)
  scope https://www.googleapis.com/auth/cloud-identity.policies.readonly
Setting read: settings/security.password, value fields (documented at
https://docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings):
  allowedStrength (STRONG | WEAK), minimumLength, maximumLength, enforceRequirementsAtLogin,
  allowReuse, expirationDuration.

Rule (fail closed): true only when at least one security.password policy is returned and EVERY
one of them (one per org unit / group it is applied to, including Google's SYSTEM default)
requires a strong password (allowedStrength STRONG), a minimum length of at least MIN_LENGTH, and
enforces the requirements at sign-in (enforceRequirementsAtLogin). One weak org unit fails the
tenant.

A security.password policy that was read and misses the standard is false (a real finding).

Not measured (key None, dataCollection error, so Token-Service shows it Not evaluated, never
Failed): a Google error or missing scope, a body that is not JSON or not a policy list, a list
that still carries nextPageToken with no weak policy in the pages read (truncated: an unread page
could hold a weak policy), a list with no security.password policy at all, and this transform's
own exception.

A weak policy already read settles the answer even when the list is truncated: the rule needs EVERY
policy to pass, so an unread page cannot undo it. That case is a measured false, and the reason says
the list was incomplete. True always needs the whole list.

Does not prove: password expiry or reuse settings, or that users have changed passwords since the
policy was tightened.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('confirmPasswordPolicyEnforced',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


CRITERIA_KEY = "confirmPasswordPolicyEnforced"
SETTING = "security.password"
MIN_LENGTH = 8
REQUIRED_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for attempt in range(4):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Google Workspace",
                         "category": "Multifactor Authentication"}
        }
    }


def error_text(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if data is None:
        return "No response body"
    if isinstance(data, str):
        return "Empty response body" if data.strip() == "" else "Response body is not JSON"
    if not isinstance(data, dict):
        return ""
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return " ".join(str(x) for x in [value.get("code") or "", value.get("status") or "",
                                             value.get("message") or ""] if x) or str(value)
        parts = [str(x) for x in [data.get("message"), data.get("error_description")] if x]
        return " ".join(parts) if parts else str(value)
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s %s" % (code, data.get("message") or "")
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return ""


def is_true(value):
    """Stored Google bodies carry booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def policy_scope(policy):
    query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
    return str(query.get("orgUnit") or query.get("group") or policy.get("name") or "unscoped")


def not_measured(reason, validation, summary=None):
    return create_response(result={CRITERIA_KEY: None}, validation=validation, api_errors=[reason],
                           fail_reasons=["Not measured: " + reason], input_summary=summary or {})


def transform(input):
    try:
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        data, validation = extract_input(input)

        error = error_text(data)
        if error:
            low = error.lower()
            if "scope" in low or "unauthorized_client" in low or "access_denied" in low:
                error = "scope not granted: %s is required. Google said: %s" % (REQUIRED_SCOPE, error[:240])
            return not_measured(error[:300], validation)
        if not isinstance(data, dict) or not isinstance(data.get("policies"), list):
            return not_measured("response is not a Cloud Identity policy list", validation)
        truncated = bool(data.get("nextPageToken"))

        checked = []
        weak = []
        weak_admin = 0  # weak policies an administrator set; Google's SYSTEM default is overridden by them
        for policy in data["policies"]:
            if not isinstance(policy, dict):
                continue
            setting = policy.get("setting") if isinstance(policy.get("setting"), dict) else {}
            if not str(setting.get("type") or "").endswith(SETTING):
                continue
            value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
            scope = policy_scope(policy)
            strength = str(value.get("allowedStrength") or "").upper()
            min_len = as_int(value.get("minimumLength"))
            enforced = is_true(value.get("enforceRequirementsAtLogin"))
            problems = []
            if strength != "STRONG":
                problems.append("allowedStrength=%s" % (strength or "missing"))
            if min_len is None or min_len < MIN_LENGTH:
                problems.append("minimumLength=%s" % (min_len if min_len is not None else "missing"))
            if not enforced:
                problems.append("enforceRequirementsAtLogin is not true")
            checked.append({"scope": scope, "allowedStrength": strength, "minimumLength": min_len,
                            "enforceRequirementsAtLogin": enforced})
            if problems:
                weak.append("%s: %s" % (scope, ", ".join(problems)))
                if str(policy.get("type") or "").upper() != "SYSTEM":
                    weak_admin += 1

        summary = {"policiesRead": len(data["policies"]), "passwordPolicies": len(checked), "weakPolicies": len(weak),
                   "truncated": truncated}
        if truncated and not weak_admin:
            return not_measured("policy list was truncated (nextPageToken present); an unread page may hold a weaker "
                                "password policy", validation, summary)
        if not checked:
            return not_measured("no %s policy was returned" % SETTING, validation, summary)
        if weak:
            note = " (the policy list was truncated; a weak policy already read settles this)" if truncated else ""
            return create_response(result={CRITERIA_KEY: False, "passwordPolicies": checked}, validation=validation,
                                   fail_reasons=["%d of %d password policies read do not meet the standard%s: %s"
                                                 % (len(weak), len(checked), note, "; ".join(weak[:10]))],
                                   recommendations=["In the Google Admin console (Security > Password management) require "
                                                    "strong passwords of at least %d characters and enforce them at next "
                                                    "sign-in for every organizational unit" % MIN_LENGTH],
                                   input_summary=summary)
        return create_response(result={CRITERIA_KEY: True, "passwordPolicies": checked}, validation=validation,
                               pass_reasons=["All %d password policies require STRONG passwords of at least %d characters "
                                             "and enforce them at sign-in" % (len(checked), MIN_LENGTH)],
                               input_summary=summary)
    except Exception as e:
        return create_response(result={CRITERIA_KEY: None}, validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=["Transformation error: %s" % str(e)])
