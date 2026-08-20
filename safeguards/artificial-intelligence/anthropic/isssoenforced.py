"""
Transformation: isSSOEnforced
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures single sign-on is enabled and enforced on every Claude surface the organization reports, so access is federated rather than optional.
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
    "transformationId": "isSSOEnforced",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


_MISSING = object()


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


ENFORCEMENT_FLAGS = ("sso_claude_ai_enforced", "sso_console_enforced")


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    settings = _settings_map(data)
    settings_count = len(settings)
    sso_enabled = settings.get("sso_enabled", _MISSING)

    if sso_enabled is _MISSING:
        return create_response(
            result={"isSSOEnforced": False, "ssoEnabled": None, "settingReported": False},
            validation=validation,
            fail_reasons=[
                "The effective organization settings response did not include an 'sso_enabled' "
                "row, so single sign-on enforcement cannot be proven for this organization."
            ],
            recommendations=["Confirm the organization's plan supports SSO, then configure and enforce it."],
            input_summary={"settingsReported": settings_count, "settingPresent": False},
            metadata=METADATA,
        )

    if not _as_bool(sso_enabled):
        return create_response(
            result={"isSSOEnforced": False, "ssoEnabled": False, "enforcedSurfaces": [], "unenforcedSurfaces": []},
            validation=validation,
            fail_reasons=["Single sign-on is disabled for this organization (sso_enabled is false)."],
            recommendations=[
                "Enable single sign-on in claude.ai > Organization settings, then turn on enforcement "
                "for both claude.ai and Claude Console."
            ],
            input_summary={"settingsReported": settings_count, "ssoEnabled": False},
            metadata=METADATA,
        )

    reported = {f: _as_bool(settings[f]) for f in ENFORCEMENT_FLAGS if f in settings}

    if not reported:
        return create_response(
            result={"isSSOEnforced": False, "ssoEnabled": True, "enforcedSurfaces": [], "unenforcedSurfaces": []},
            validation=validation,
            fail_reasons=[
                "Single sign-on is enabled but neither sso_claude_ai_enforced nor sso_console_enforced "
                "was reported, so enforcement cannot be proven. SSO that is available but not enforced "
                "is a login option, not an access control."
            ],
            recommendations=["Enforce SSO for claude.ai and Claude Console in claude.ai > Organization settings."],
            input_summary={"settingsReported": settings_count, "ssoEnabled": True, "flagsReported": 0},
            metadata=METADATA,
        )

    enforced = sorted(f for f, v in reported.items() if v)
    unenforced = sorted(f for f, v in reported.items() if not v)
    result = not unenforced

    if result:
        pass_reasons = [
            "Single sign-on is enabled and enforced on every reported surface (" +
            ", ".join(enforced) + ")."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "Single sign-on is enabled but not enforced on " + str(len(unenforced)) +
            " reported surface(s): " + ", ".join(unenforced) + ". Users on those surfaces can "
            "still authenticate outside the identity provider."
        ]
        recommendations = [
            "Turn on SSO enforcement for " + ", ".join(unenforced) +
            " in claude.ai > Organization settings."
        ]

    return create_response(
        result={
            "isSSOEnforced": result,
            "ssoEnabled": True,
            "enforcedSurfaces": enforced,
            "unenforcedSurfaces": unenforced,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"settingsReported": settings_count, "flagsReported": len(reported)},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isSSOEnforced": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
