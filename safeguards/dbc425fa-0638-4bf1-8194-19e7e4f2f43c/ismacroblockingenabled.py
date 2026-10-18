"""
Transformation: isMacroBlockingEnabled
Vendor: Google Workspace
Category: Email Security

Evidence: getMailPolicies, the Cloud Identity Policy API filtered to gmail.* settings.
Judged setting: gmail.email_attachment_safety
Required fields (each must equal "True"): enableAttachmentWithScriptsProtection

Gmail has no switch that blocks Office macros as such. The nearest control is "Protect against
attachments with scripts from untrusted senders" (enableAttachmentWithScriptsProtection), which
covers macro-bearing Office files. PROXY: it can warn rather than block, and the consequence is
reported in the evidence, not judged.

Rule (fail closed): true only when at least one gmail.email_attachment_safety policy is returned and EVERY one of them
in force (Google returns several per org unit or group: SYSTEM defaults and any ADMIN override; the
one with the greatest policyQuery.sortOrder is applied and is the only one judged) has all required fields "True". A policy
that reports a required field off, or a complete list that carries no policy for this setting, is false:
those are measured. A required field a policy does not report at all is not off, it is unknown (None).

Not measured (key None and dataCollection error, so Token-Service shows Not evaluated, never Failed):
a Google error or refusal, a missing scope, a body that is not JSON or not a policy list, an empty
policy list, a list with no policy record in it, a policy that does not report a required field (and no
policy reports one off), a list still carrying nextPageToken (or paginationTruncated), and this transform's
own exception. A truncated list is never judged, even when a policy read so far is off: a later page can
hold the only policy for this setting, or one with a greater sortOrder for the same org unit that
supersedes a policy read here.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isMacroBlockingEnabled"
SETTING_TYPE = "gmail.email_attachment_safety"
REQUIRED_FIELDS = ['enableAttachmentWithScriptsProtection']
CONTROL = "Script-attachment protection"
ADVICE = "In Admin console > Apps > Google Workspace > Gmail > Safety > Attachments, turn on protection against attachments with scripts from untrusted senders"


#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isMacroBlockingEnabled',)


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


def as_order(value):
    """policyQuery.sortOrder as a number; None when unreadable. Integration-Service hands scalars over as strings."""
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def in_force(matched):
    """Split matched policies into the ones Google applies and the ones they supersede.

    For one setting on one org unit (or group) Google returns several policies: the SYSTEM default for
    entities without a Gmail licence, the SYSTEM default for licensed users, and any ADMIN override. It
    resolves them by precedence: the policy with the greatest policyQuery.sortOrder is the one in force
    (Policy API concepts, Max reducer), so only that one is judged. Equal sortOrders on one target, and a
    sortOrder that cannot be read, are all judged (fail closed). Returns (judged, superseded).
    """
    top = {}
    for target, value, order, policy_type in matched:
        if order is not None and (target not in top or order > top[target]):
            top[target] = order
    judged = []
    superseded = []
    for entry in matched:
        target, value, order, policy_type = entry
        if order is None or target not in top or order >= top[target]:
            judged.append(entry)
        else:
            superseded.append(entry)
    return judged, superseded


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
        if is_truncated(data):
            # More pages exist. A later page could hold the only policy for this setting, or one with a greater
            # sortOrder that supersedes a policy read here, so nothing read so far decides the result.
            return unmeasured("The policy list was truncated (nextPageToken present) before every %s policy was "
                              "read; %s not evaluated across all org units" % (SETTING_TYPE, CONTROL), validation,
                              {"truncated": True})

        matched = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            setting = policy.get("setting")
            if not isinstance(setting, dict) or not str(setting.get("type", "")).endswith(SETTING_TYPE):
                continue
            value = setting.get("value")
            query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
            target = str(query.get("orgUnit") or "unknown")
            if query.get("group"):
                target = target + " " + str(query.get("group"))
            matched.append((target, value if isinstance(value, dict) else {},
                            as_order(query.get("sortOrder")), str(policy.get("type") or "")))
        # Judge only the policy in force on each org unit or group; Google's own precedence decides which.
        matched, superseded = in_force(matched)

        findings = []
        off_fields = []
        missing_fields = []
        compliant = 0
        for org_unit, value, order, policy_type in matched:
            # A field the policy reports as off is a finding. A field it does not report at all is not: it
            # leaves the policy unjudged (None), never off.
            off = [f for f in REQUIRED_FIELDS if value.get(f) is not None and not is_true(value.get(f))]
            absent = [f for f in REQUIRED_FIELDS if value.get(f) is None]
            for f in off:
                if f not in off_fields:
                    off_fields.append(f)
            for f in absent:
                if f not in missing_fields:
                    missing_fields.append(f)
            if not off and not absent:
                compliant = compliant + 1
            if off:
                state, reason = False, "off: " + ", ".join(off)
            elif absent:
                state, reason = None, "not reported: " + ", ".join(absent)
            else:
                state, reason = True, "all required settings on"
            findings.append({"metric": org_unit, "value": state, "reason": reason,
                             "policyType": policy_type, "sortOrder": order})

        if off_fields:
            # A policy in force that reports a required field off decides False, whatever else is unreported.
            result_value = False
        elif len(matched) == 0:
            # A complete list that carries no policy for this setting is a proven negative.
            result_value = False
        elif missing_fields:
            return unmeasured("A %s policy did not report %s, so %s cannot be judged" % (
                SETTING_TYPE, ", ".join(missing_fields), CONTROL.lower()), validation,
                {"gmailPolicies": len(policies), "matchingPolicies": len(matched)})
        else:
            result_value = True

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
            input_summary={"gmailPolicies": len(policies), "matchingPolicies": len(matched), "compliant": compliant,
                           "supersededPolicies": len(superseded)}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
