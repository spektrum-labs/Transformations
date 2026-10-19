"""
Transformation: authTypesAllowed
Vendor: Google Workspace (Cloud Identity Policy API)
Category: Multifactor Authentication / Identity

Evidence: getPolicies
  GET https://cloudidentity.googleapis.com/v1beta1/policies  (paged: pageSize/pageToken)
  scope https://www.googleapis.com/auth/cloud-identity.policies.readonly
Settings read (https://docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings):
  settings/security.two_step_verification_enforcement_factor  allowedSignInFactorSet
      ALL | NO_TELEPHONY | PASSKEY_ONLY | PASSKEY_PLUS_SECURITY_CODE | PASSKEY_PLUS_IP_BOUND_SECURITY_CODE
  settings/security.two_step_verification_enrollment           allowEnrollment

Rule (same meaning as the Okta and Azure files: only strong authenticators may be used): true
only when at least one 2-Step Verification factor policy is returned, EVERY factor policy (one per
org unit / group, including the SYSTEM default) restricts sign-in to a set that excludes SMS and
voice codes (anything but ALL), and no enrollment policy forbids 2-Step Verification
(allowEnrollment false leaves those users with a password only). An unknown factor-set value
fails.

A factor policy that was read and allows SMS or voice codes, an unknown factor-set value, or an
enrollment policy that forbids 2-Step Verification is false (a real finding).

Not measured (key None, dataCollection error, so Token-Service shows it Not evaluated, never
Failed): a Google error or missing scope, a body that is not JSON or not a policy list, a list
that still carries nextPageToken with no weak policy in the pages read, a list with no 2-Step
Verification factor policy, and this transform's own exception.

A weak factor policy or a disabled enrollment already read settles the answer even when the list is
truncated: the rule needs EVERY policy to pass, so an unread page cannot undo it. That case is a
measured false, and the reason says the list was incomplete. True always needs the whole list.

Does not prove: that 2-Step Verification is enforced (security.two_step_verification_enforcement;
that is isMFAEnforcedForUsers), or which factors users actually enrolled.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('authTypesAllowed',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


CRITERIA_KEY = "authTypesAllowed"
FACTOR_SETTING = "security.two_step_verification_enforcement_factor"
ENROLL_SETTING = "security.two_step_verification_enrollment"
STRONG_SETS = ["NO_TELEPHONY", "PASSKEY_ONLY", "PASSKEY_PLUS_SECURITY_CODE", "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE"]
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

        factor_sets = []
        weak = []
        no_enrollment = []
        admin_problems = 0  # problems in policies an administrator set; Google's SYSTEM default is overridden by them
        for policy in data["policies"]:
            if not isinstance(policy, dict):
                continue
            setting = policy.get("setting") if isinstance(policy.get("setting"), dict) else {}
            kind = str(setting.get("type") or "")
            value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
            scope = policy_scope(policy)
            if kind.endswith(FACTOR_SETTING):
                factor_set = str(value.get("allowedSignInFactorSet") or "").upper()
                factor_sets.append({"scope": scope, "allowedSignInFactorSet": factor_set or None})
                if factor_set not in STRONG_SETS:
                    weak.append("%s: allowedSignInFactorSet=%s" % (scope, factor_set or "missing"))
                    if str(policy.get("type") or "").upper() != "SYSTEM":
                        admin_problems += 1
            elif kind.endswith(ENROLL_SETTING):
                if "allowEnrollment" in value and not is_true(value.get("allowEnrollment")):
                    no_enrollment.append("%s: allowEnrollment=false" % scope)
                    if str(policy.get("type") or "").upper() != "SYSTEM":
                        admin_problems += 1

        summary = {"policiesRead": len(data["policies"]), "factorPolicies": len(factor_sets),
                   "weakFactorPolicies": len(weak), "enrollmentDisabled": len(no_enrollment), "truncated": truncated}
        problems = weak + no_enrollment
        if truncated and not admin_problems:
            return not_measured("policy list was truncated (nextPageToken present); an unread page may allow SMS or "
                                "voice codes", validation, summary)
        if not factor_sets and not truncated:
            return not_measured("no %s policy was returned" % FACTOR_SETTING, validation, summary)
        if problems:
            note = " (the policy list was truncated; a weak policy already read settles this)" if truncated else ""
            return create_response(result={CRITERIA_KEY: False, "factorPolicies": factor_sets}, validation=validation,
                                   fail_reasons=["Weak or password-only sign-in is allowed%s: %s" % (note, "; ".join(problems[:10]))],
                                   recommendations=["In the Google Admin console (Security > 2-Step Verification) allow 2-Step "
                                                    "Verification everywhere and set Methods to exclude text message and "
                                                    "phone call codes (for example passkeys only) for every organizational unit"],
                                   input_summary=summary)
        return create_response(result={CRITERIA_KEY: True, "factorPolicies": factor_sets}, validation=validation,
                               pass_reasons=["All %d 2-Step Verification method policies exclude SMS and voice codes (%s)"
                                             % (len(factor_sets), ", ".join(sorted(set(f["allowedSignInFactorSet"] for f in factor_sets))))],
                               input_summary=summary)
    except Exception as e:
        return create_response(result={CRITERIA_KEY: None}, validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=["Transformation error: %s" % str(e)])
