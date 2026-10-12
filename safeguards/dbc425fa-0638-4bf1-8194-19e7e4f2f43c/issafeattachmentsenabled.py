"""
Transformation: isSafeAttachmentsEnabled
Vendor: Google Workspace
Category: Email Security

Evidence: getMailPolicies, the Cloud Identity Policy API filtered to gmail.* settings.
Judged setting: gmail.email_attachment_safety
Required fields (each must equal "True"): enableEncryptedAttachmentProtection, enableAttachmentWithScriptsProtection, enableAnomalousAttachmentProtection

Reads the three Gmail "Attachments" safety protections: encrypted attachments from untrusted senders,
attachments with scripts, and anomalous attachment types. All three must be on.
PROXY: this is not sandbox detonation. Google Security Sandbox (Enterprise editions) is not exposed
in this policy set, so a true sandbox cannot be proven from this evidence.

Rule (fail closed): true only when at least one gmail.email_attachment_safety policy is returned and EVERY one of them
(Google returns one per org unit or group that sets it) has all required fields "True". A missing
field, a policy with a required field off, or a complete list that carries no policy for this setting
is false: those are measured.

Not measured (key None and dataCollection error, so Token-Service shows Not evaluated, never Failed):
a Google error or refusal, a missing scope, a body that is not JSON or not a policy list, an empty
policy list, a list with no policy record in it, a list still carrying nextPageToken in which no policy
is off yet (more pages could hold one), and this transform's own exception.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isSafeAttachmentsEnabled"
SETTING_TYPE = "gmail.email_attachment_safety"
REQUIRED_FIELDS = ['enableEncryptedAttachmentProtection', 'enableAttachmentWithScriptsProtection', 'enableAnomalousAttachmentProtection']
CONTROL = "Attachment protection"
ADVICE = "In Admin console > Apps > Google Workspace > Gmail > Safety > Attachments, turn on all three protections; consider Security Sandbox where the edition allows"


#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isSafeAttachmentsEnabled',)


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
        for attempt in range(3):
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
                "transformationId": CRITERIA_KEY,
                "vendor": "Google Workspace",
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
    """The read could not answer: key None and a dataCollection error, so it shows as Not evaluated."""
    return create_response(
        result={CRITERIA_KEY: None},
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        input_summary=summary
    )


def is_true(value):
    """Cloud Identity returns booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        error = vendor_error(data)
        if error is None and not isinstance(data, (dict, list)):
            error = "Response is not a policy list"
        if error is not None:
            return unmeasured(error, validation)

        policies = data if isinstance(data, list) else data.get("policies")
        if not isinstance(policies, list):
            return unmeasured("No policies list in the response: the Gmail settings read cannot be shown to have run",
                              validation)
        if not [p for p in policies if isinstance(p, dict)]:
            return unmeasured("No Gmail policies were returned: an empty list cannot be told apart from a read "
                              "that returned nothing", validation)
        truncated = is_truncated(data)

        matched = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            setting = policy.get("setting")
            if not isinstance(setting, dict) or not str(setting.get("type", "")).endswith(SETTING_TYPE):
                continue
            value = setting.get("value")
            query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
            matched.append((str(query.get("orgUnit") or query.get("group") or "unknown"), value if isinstance(value, dict) else {}))

        findings = []
        off_fields = []
        compliant = 0
        for org_unit, value in matched:
            off = [f for f in REQUIRED_FIELDS if not is_true(value.get(f))]
            for f in off:
                if f not in off_fields:
                    off_fields.append(f)
            if not off:
                compliant = compliant + 1
            findings.append({
                "metric": org_unit,
                "value": not off,
                "reason": "all required settings on" if not off else "off or missing: " + ", ".join(off)
            })

        result_value = len(matched) > 0 and compliant == len(matched)
        if truncated and (len(matched) == 0 or result_value):
            # More pages exist. A policy that is off already decides False; nothing read so far can prove
            # True, or prove that no policy for this setting exists.
            return unmeasured("The policy list was truncated (nextPageToken present) before every %s policy was "
                              "read; %s not evaluated across all org units" % (SETTING_TYPE, CONTROL), validation,
                              {"gmailPolicies": len(policies), "matchingPolicies": len(matched)})
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("%s on in all %d %s policies" % (CONTROL, len(matched), SETTING_TYPE))
        elif len(matched) == 0:
            fail_reasons.append("No %s policy returned (%d Gmail policies read); %s not proven" % (SETTING_TYPE, len(policies), CONTROL))
            recommendations.append(ADVICE)
        else:
            fail_reasons.append("%s not fully on in %d of %d %s policies (off: %s)" % (
                CONTROL, len(matched) - compliant, len(matched), SETTING_TYPE, ", ".join(off_fields)))
            recommendations.append(ADVICE)

        return create_response(
            result={CRITERIA_KEY: result_value, "policiesJudged": len(matched), "policiesCompliant": compliant},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={"gmailPolicies": len(policies), "matchingPolicies": len(matched), "compliant": compliant}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
