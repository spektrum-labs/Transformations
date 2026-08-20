"""
Transformation: isSkillGovernanceEnforced
Vendor: Anthropic  |  Category: Artificial Intelligence
Product: Claude
Evaluates: Ensures user-authored skills cannot be created or shared organization-wide without governance, or that skills are disabled entirely.
API Source: getEffectiveOrganizationSettings
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    "transformationId": "isSkillGovernanceEnforced",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


_MISSING = object()

# HTTP status -> why the call was refused. These are NOT posture findings: they mean
# the credential or tenancy cannot reach the endpoint, so the control is UNKNOWN
# rather than absent. Anthropic's compliance org-data endpoints (settings, groups,
# organizations, users) accept only a Compliance Access Key (sk-ant-api01-...)
# created in claude.ai; an Admin API key (sk-ant-admin01-...) gets 403, and a
# standalone Claude Console organization can reach the Activity Feed only.
_REFUSAL = {
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


def _refusal(data):
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
    why, fix = _REFUSAL.get(status, (
        "the vendor call did not succeed",
        "Inspect the integration method response for the underlying error."))
    detail = data.get("message") or data.get("errorMessage") or ""
    if detail:
        why = why + " (" + str(detail) + ")"
    return status, why, fix


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "enabled", "on")
    return bool(value)


def _settings_map(data):
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
            out[row["name"]] = row.get("value", _MISSING)
    return out


UNGOVERNED_FLAGS = ("user_skill_creation_enabled", "org_wide_skill_sharing_enabled")


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    refusal = _refusal(data)
    if refusal:
        _status, _why, _fix = refusal
        return create_response(
            result={"isSkillGovernanceEnforced": False, "endpointReachable": False, "httpStatus": _status},
            validation=validation,
            fail_reasons=[
                "The organization settings could not be read because " + _why +
                ". This is a connectivity or credential-scope result, not a finding about "
                "the organization's configuration - the control's real state is unknown."
            ],
            recommendations=[_fix],
            input_summary={"endpointReachable": False, "httpStatus": _status},
            metadata=METADATA,
        )

    settings = _settings_map(data)
    settings_count = len(settings)
    skills_raw = settings.get("skills_enabled", _MISSING)
    reported = {f: _as_bool(settings[f]) for f in UNGOVERNED_FLAGS if f in settings}

    if skills_raw is _MISSING and not reported:
        return create_response(
            result={"isSkillGovernanceEnforced": False, "skillsEnabled": None, "ungovernedFlags": []},
            validation=validation,
            fail_reasons=[
                "Neither 'skills_enabled' nor any skill governance flag (" +
                ", ".join(UNGOVERNED_FLAGS) + ") was reported, so skill governance cannot be proven."
            ],
            recommendations=["Confirm the organization's plan exposes the skill controls."],
            input_summary={"settingsReported": settings_count, "settingPresent": False},
            metadata=METADATA,
        )

    skills_on = None if skills_raw is _MISSING else _as_bool(skills_raw)

    if skills_on is False:
        return create_response(
            result={"isSkillGovernanceEnforced": True, "skillsEnabled": False, "ungovernedFlags": []},
            validation=validation,
            pass_reasons=["Skills are disabled organization-wide, so no ungoverned skill can be authored or shared."],
            input_summary={"settingsReported": settings_count, "skillsEnabled": False},
            metadata=METADATA,
        )

    if not reported:
        return create_response(
            result={"isSkillGovernanceEnforced": False, "skillsEnabled": skills_on, "ungovernedFlags": []},
            validation=validation,
            fail_reasons=[
                "Skills are enabled (or their state is unreported) but neither user_skill_creation_enabled "
                "nor org_wide_skill_sharing_enabled was returned, so governance over authored skills "
                "cannot be proven."
            ],
            recommendations=["Confirm the organization's plan exposes the skill governance controls."],
            input_summary={"settingsReported": settings_count, "skillsEnabled": skills_on},
            metadata=METADATA,
        )

    ungoverned = sorted(f for f, v in reported.items() if v)
    result = not ungoverned

    if result:
        pass_reasons = [
            "Skills are available but ungoverned authoring and sharing are both off (" +
            ", ".join(sorted(reported.keys())) + " all false)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "Skills are available with ungoverned capability enabled: " + ", ".join(ungoverned) +
            ". Any member can author and distribute instructions that other members' agents will follow."
        ]
        recommendations = [
            "Disable " + ", ".join(ungoverned) + " in claude.ai > Organization settings, or turn "
            "skills off entirely if they are not in use."
        ]

    return create_response(
        result={
            "isSkillGovernanceEnforced": result,
            "skillsEnabled": skills_on,
            "ungovernedFlags": ungoverned,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"settingsReported": settings_count, "skillsEnabled": skills_on},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isSkillGovernanceEnforced": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
