"""
Transformation: isGroupProvisioningManaged
Vendor: Anthropic  |  Category: Artificial Intelligence
Product: Claude
Evaluates: Ensures access groups are provisioned from the identity provider through SCIM rather than maintained by hand inside Claude.
API Source: listComplianceGroups
Not evaluated, never False on a read that proves nothing: a refused call (401/403/404/429),
an empty or unrecognised body, a page that says more groups exist while every group seen is
SCIM, a group whose source_type is missing or unknown, and an exception inside this file all
answer None with dataCollection.status "error", which Token-Service records as not evaluated.
False only when a readable group carries source_type "direct".
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    # Decode a JSON string or bytes BEFORE inspecting shape. Without this a str body
    # matches no branch here, stays a str, and every caller's `isinstance(data, dict)`
    # test fails -- so a perfectly good response is read as "nothing came back" and the
    # criterion is answered from an empty shape. CLAUDE.md's `_parse_input` pattern makes
    # str, bytes and dict equivalent everywhere else in this repo; this family did not.
    # A string that is not JSON raises into each transform's existing handler: fail closed.
    if isinstance(input_data, (str, bytes)):
        if isinstance(input_data, bytes):
            input_data = input_data.decode("utf-8")
        input_data = json.loads(input_data)
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


METADATA = {
    "transformationId": "isGroupProvisioningManaged",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


# Unique sentinel. object() is unavailable in the RestrictedPython sandbox
# Token-Service runs transforms in, so a fresh list is used instead: a list
# literal is never interned, which keeps the "is MISSING" identity checks valid.
MISSING = ["__missing__"]

# HTTP status -> why the call was refused. These are NOT posture findings: they mean
# the credential or tenancy cannot reach the endpoint, so the control is UNKNOWN
# rather than absent. Anthropic's compliance org-data endpoints (settings, groups,
# organizations, users) accept only a Compliance Access Key (sk-ant-api01-...)
# created in claude.ai; an Admin API key (sk-ant-admin01-...) gets 403, and a
# standalone Claude Console organization can reach the Activity Feed only.
REFUSAL_REASONS = {
    401: ("the credential was rejected",
          "Confirm the key is an admin-class key and has not been revoked or expired."),
    403: ("this organization's credential is not permitted to call the endpoint",
          "This endpoint requires a Compliance Access Key (sk-ant-api01-...) created in "
          "claude.ai > Organization settings > API with the read:org_audit scope. An Admin "
          "API key (sk-ant-admin01-...) from Claude Console returns 403 here. A standalone "
          "Claude Console organization cannot read these settings at all - treat this "
          "criterion as not applicable for that tenant rather than failed."),
    404: ("the endpoint or organization was not found",
          "Check the Organization ID. The compliance endpoints take a compliance "
          "organization uuid from GET /v1/compliance/organizations, which is a different "
          "value from the Console organization id shown at "
          "platform.claude.com/settings/organization."),
    429: ("the vendor rate-limited the call",
          "Compliance endpoints allow 600 requests/minute per parent organization. Retry."),
}


def detect_refusal(data):
    """Return (status, why, fix) when the payload is an error envelope, else None."""
    if not isinstance(data, dict):
        return None
    if not (data.get("error") or data.get("errorType") or data.get("status") == "Error"):
        return None
    status = data.get("statusCode") or data.get("status_code")
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    why, fix = REFUSAL_REASONS.get(status, (
        "the vendor call did not succeed",
        "Inspect the integration method response for the underlying error."))
    # The vendor's own message is not copied into the reason: it is free text from the
    # vendor and can echo request details. The HTTP status carries the diagnosis.
    return status, why, fix


def as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "enabled", "on")
    return bool(value)


def settings_map(data):
    """Reduce the effective-settings rows to {name: value}.

    A setting this organization's administrators cannot change is omitted from
    the response entirely, so a missing name means "not controllable here",
    never "off". Callers must distinguish absent from False, which is why this
    returns a plain dict and callers use the _MISSING sentinel.
    """
    rows = None
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for key in ("data", "settings"):
            if isinstance(data.get(key), list):
                rows = data[key]
                break
    if rows is None:
        rows = []
    out = {}
    for row in rows:
        if isinstance(row, dict) and row.get("name") is not None:
            out[row["name"]] = row.get("value", MISSING)
    return out


def not_measured(validation, reason, recommendation, extra=None, input_summary=None,
                 transformation_errors=None):
    """No verdict: the key is None and dataCollection.status is "error", so the evaluator
    shows Not evaluated instead of a failed check. extra carries facts really read."""
    result = {"isGroupProvisioningManaged": None}
    if extra:
        result.update(extra)
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[reason],
        recommendations=[recommendation] if recommendation else [],
        input_summary=input_summary or {},
        metadata=METADATA,
        api_errors=[reason],
        transformation_errors=transformation_errors,
    )


def group_list(data):
    """(groups, truncated) from a bare list or a {data|groups: [...], has_more, next_page} page.

    groups is None when no list is recognised. truncated is True when the page says more
    groups exist (has_more true or a next_page token), so an all-SCIM page cannot prove all.
    """
    items = None
    truncated = False
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data")
        if not isinstance(items, list):
            items = data.get("groups")
        truncated = data.get("has_more") is True or bool(data.get("next_page"))
    if not isinstance(items, list):
        return None, False
    return [g for g in items if isinstance(g, dict)], truncated


def group_label(g):
    return str(g.get("name") or g.get("id") or "unnamed")


def evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    refusal = detect_refusal(data)
    if refusal:
        refusal_status, refusal_why, refusal_fix = refusal
        return not_measured(
            validation,
            "The vendor call did not return data because " + refusal_why +
            ". This is a connectivity or credential-scope result, not a finding about "
            "the organization's configuration - the control's real state is unknown.",
            refusal_fix,
            extra={"endpointReachable": False, "httpStatus": refusal_status},
            input_summary={"endpointReachable": False, "httpStatus": refusal_status},
        )

    groups, truncated = group_list(data)
    if groups is None:
        return not_measured(
            validation,
            "The GET /v1/compliance/groups response was not recognised - no groups list in the "
            "payload - so identity-provider group provisioning was not evaluated.",
            "Inspect the raw integration response.",
        )

    if not groups:
        # An empty list proves nothing about how groups would be provisioned: a key without
        # the right scope, an organization not using groups yet and an empty page all look
        # the same. No verdict.
        return not_measured(
            validation,
            "GET /v1/compliance/groups returned no groups, so identity-provider group "
            "provisioning could not be assessed.",
            "Confirm the key carries read:compliance_org_data, and that the organization uses "
            "groups for access control.",
            extra={"groupCount": 0, "scimGroupCount": 0, "directGroups": []},
            input_summary={"groupCount": 0},
        )

    # Anthropic documents two source_type values, "scim" and "direct". Anything else is
    # unreadable, not direct: it cannot make the answer False on its own.
    scim = [group_label(g) for g in groups if str(g.get("source_type", "")).lower() == "scim"]
    direct = [group_label(g) for g in groups if str(g.get("source_type", "")).lower() == "direct"]
    unknown = [group_label(g) for g in groups
               if str(g.get("source_type", "")).lower() not in ("scim", "direct")]

    if not direct and (unknown or truncated):
        if unknown:
            why = (str(len(unknown)) + " of " + str(len(groups)) + " group(s) carry no recognised "
                   "source_type, so whether they are provisioned through SCIM was not read.")
        else:
            why = ("The groups response says more groups exist beyond this page, and every group "
                   "on it is SCIM-provisioned; the unread groups could be maintained by hand.")
        return not_measured(
            validation,
            why + " Identity-provider group provisioning was not evaluated.",
            "Re-run the evaluation so every page of GET /v1/compliance/groups is read.",
            # A page count is not the population when more pages exist, so counts are only
            # reported as results when the list is complete.
            extra=({"directGroups": []} if truncated else
                   {"groupCount": len(groups), "scimGroupCount": len(scim), "directGroups": []}),
            input_summary={"groupCount": len(groups), "scimGroupCount": len(scim),
                           "unreadGroupCount": len(unknown), "truncated": truncated},
        )

    result = not direct

    if result:
        pass_reasons = [
            "All " + str(len(groups)) + " group(s) are provisioned through SCIM directory sync: " +
            ", ".join(sorted(scim)) + ". Membership is owned by the identity provider and cannot "
            "be edited inside Claude."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            str(len(direct)) + " of " + str(len(groups)) + " group(s) are maintained directly "
            "inside Claude rather than provisioned from the identity provider: " +
            ", ".join(sorted(direct)) + ". Their membership is not governed by the joiner-mover-leaver process."
        ]
        recommendations = [
            "Migrate the listed groups to SCIM provisioning in the identity provider, or document "
            "why they are managed by hand."
        ]

    return create_response(
        result={
            "isGroupProvisioningManaged": result,
            "groupCount": len(groups),
            "scimGroupCount": len(scim),
            "directGroups": sorted(direct),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"groupCount": len(groups), "scimGroupCount": len(scim)},
        metadata=METADATA,
    )


def transform(input):
    try:
        return evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return not_measured(
            {"status": "error", "errors": [], "warnings": []},
            "The groups response could not be read, so the "
            "control's state is unknown.",
            "Report this to the Spektrum integrations team with the raw API response.",
            transformation_errors=[str(exc)],
        )
