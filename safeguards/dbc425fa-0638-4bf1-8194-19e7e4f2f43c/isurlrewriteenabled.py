"""
Transformation: isURLRewriteEnabled
Vendor: Google Workspace
Category: Email Security

Evaluates whether Gmail checks links before delivery.

Google Workspace has no literal "URL rewrite" the way a mail gateway does. The
equivalent control is the Gmail "Links and external images" safety policy, which
scans links behind shorteners and warns on untrusted links. It is exposed by the
Cloud Identity Policy API as settings/gmail.links_and_external_images.

Google returns several policies for the setting on one org unit (SYSTEM defaults for unlicensed and
licensed entities, and any ADMIN override) and applies the one with the greatest policyQuery.sortOrder;
only that policy is judged per org unit or group.

Previously this transform read a top-level "urlRewrite" field from the mail-server
DNS tool, which never returns one, so the criterion was false for every customer.

False (measured) when a link-protection policy was read and a required setting is off, or a
complete policy list was read that carries no link-protection policy. A required setting a policy
does not report at all is not off, it is unknown (None).

Not measured (key None and dataCollection error, so Token-Service shows Not evaluated, never
Failed): a Google error or refusal, a body that is not JSON or not a policy list, an empty policy
list, a failed input validation, a link-protection policy that does not report a required setting (and
none reports one off), a list still carrying nextPageToken (or paginationTruncated), since a later page
could still hold a policy, and this transform's own exception. A truncated list is never judged, even
when a policy read so far is off: a later page can hold a policy with a greater sortOrder for the same
org unit that supersedes it.
"""

import json
from datetime import datetime

SETTING_TYPE = "gmail.links_and_external_images"

# Fields that constitute "URLs are checked before delivery". External image
# scanning is deliberately excluded: it governs images, not links.
REQUIRED_FIELDS = ["enableShortenerScanning", "enableAggressiveWarningsOnUntrustedLinks"]

CRITERIA_KEY = "isURLRewriteEnabled"

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isURLRewriteEnabled',)


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
                "transformationId": "isURLRewriteEnabled",
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
    """The read could not answer: key None and a dataCollection error, so it shows as Not evaluated."""
    return create_response(
        result={CRITERIA_KEY: None},
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        input_summary=summary
    )


def transform(input):
    criteriaKey = CRITERIA_KEY

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return unmeasured("Input validation failed", validation)

        error = vendor_error(data)
        if error is None and not isinstance(data, (dict, list)):
            error = "Response is not a policy list"
        if error is not None:
            return unmeasured(error, validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if isinstance(data, dict):
            policies = data.get("policies")
        else:
            # Token-Service can hand list-shaped API data straight through
            policies = data
        if not isinstance(policies, list):
            return unmeasured("No policies list in the response: the Gmail settings read cannot be shown to have run",
                              validation)
        if not [p for p in policies if isinstance(p, dict)]:
            return unmeasured("No Gmail policies were returned: an empty list cannot be told apart from a read "
                              "that returned nothing", validation)
        if is_truncated(data):
            # More pages exist. A later page could hold a link-protection policy, the only one, or one with a
            # greater sortOrder that supersedes a policy read here, so nothing read so far decides the result.
            return unmeasured("The policy list was truncated (nextPageToken present) before every %s policy was "
                              "read; link checking not evaluated across all org units" % SETTING_TYPE, validation,
                              {"truncated": True})

        # Collect every link-protection policy. Google returns several per org unit (SYSTEM defaults and
        # any ADMIN override); only the one in force on each org unit is judged, and the tenant is covered
        # when every one of those has link checking on.
        link_policies = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            setting = policy.get("setting", {})
            if not isinstance(setting, dict):
                continue
            if str(setting.get("type", "")).endswith(SETTING_TYPE):
                value = setting.get("value", {})
                query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
                target = str(query.get("orgUnit") or "unknown")
                if query.get("group"):
                    target = target + " " + str(query.get("group"))
                link_policies.append({
                    "orgUnit": target,
                    "value": value if isinstance(value, dict) else {},
                    "order": as_order(query.get("sortOrder")),
                    "policyType": str(policy.get("type") or "")
                })
        # Judge only the policy in force on each org unit or group; Google's own precedence decides which.
        link_policies, superseded = in_force(link_policies)

        enabled_count = 0
        disabled_fields = []
        missing_fields = []

        for entry in link_policies:
            value = entry["value"]
            # A setting the policy reports as off is a finding. One it does not report at all leaves the
            # policy unjudged (None), never off.
            off = [f for f in REQUIRED_FIELDS if value.get(f) is not None and not is_true(value.get(f))]
            absent = [f for f in REQUIRED_FIELDS if value.get(f) is None]
            for field in off:
                if field not in disabled_fields:
                    disabled_fields.append(field)
            for field in absent:
                if field not in missing_fields:
                    missing_fields.append(field)
            entry_enabled = not off and not absent
            if entry_enabled:
                enabled_count += 1
            additional_findings.append({
                "metric": entry["orgUnit"],
                "value": False if off else (None if absent else True),
                "reason": "Link checking not fully enabled" if off else (
                    "Link checking settings not reported: " + ", ".join(absent) if absent else "Link checking enabled"),
                "policyType": entry["policyType"],
                "sortOrder": entry["order"]
            })

        if disabled_fields:
            # A policy in force that reports a required setting off decides False, whatever else is unreported.
            is_url_rewrite_enabled = False
        elif len(link_policies) == 0:
            # A complete list that carries no link-protection policy is a proven negative.
            is_url_rewrite_enabled = False
        elif missing_fields:
            return unmeasured("A %s policy did not report %s, so link checking cannot be judged"
                              % (SETTING_TYPE, ", ".join(missing_fields)), validation,
                              {"totalPolicies": len(policies), "linkPolicies": len(link_policies)})
        else:
            is_url_rewrite_enabled = True

        if is_url_rewrite_enabled:
            pass_reasons.append(
                "Gmail link protection enabled across all %d org unit policies" % len(link_policies)
            )
        elif len(link_policies) == 0:
            fail_reasons.append(
                "No %s policy returned; cannot confirm links are checked before delivery" % SETTING_TYPE
            )
            recommendations.append(
                "Verify the Cloud Identity Policy API returns Gmail safety policies for this tenant"
            )
        else:
            fail_reasons.append(
                "Link checking not enabled on %d of %d org unit policies (missing: %s)"
                % (len(link_policies) - enabled_count, len(link_policies), ", ".join(disabled_fields))
            )
            recommendations.append(
                "In Admin console > Apps > Google Workspace > Gmail > Safety > Links and external "
                "images, enable shortener scanning and aggressive warnings on untrusted links"
            )

        return create_response(
            result={
                criteriaKey: is_url_rewrite_enabled,
                "linkPolicyCount": len(link_policies),
                "enabledPolicyCount": enabled_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPolicies": len(policies),
                "linkPolicies": len(link_policies),
                "enabledPolicies": enabled_count,
                "supersededPolicies": len(superseded)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
