"""
Transformation: isSessionDurationLimited
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures authenticated sessions expire within the maximum permitted window rather than persisting indefinitely.
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
    "transformationId": "isSessionDurationLimited",
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


MAX_SESSION_SECONDS = 86400  # 24 hours


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    settings = _settings_map(data)
    settings_count = len(settings)
    raw = settings.get("account_session_duration_seconds", _MISSING)

    if raw is _MISSING:
        return create_response(
            result={"isSessionDurationLimited": False, "sessionDurationSeconds": None,
                    "maxAllowedSeconds": MAX_SESSION_SECONDS},
            validation=validation,
            fail_reasons=[
                "The effective organization settings response did not include an "
                "'account_session_duration_seconds' row, so a session lifetime cap cannot be proven."
            ],
            recommendations=["Confirm the organization's plan exposes the session duration control."],
            input_summary={"settingsReported": settings_count, "settingPresent": False},
            metadata=METADATA,
        )

    if raw is None:
        return create_response(
            result={"isSessionDurationLimited": False, "sessionDurationSeconds": None,
                    "maxAllowedSeconds": MAX_SESSION_SECONDS},
            validation=validation,
            fail_reasons=[
                "No session duration limit is in force: account_session_duration_seconds is null, "
                "which Anthropic documents as no limit. Sessions persist until explicitly revoked."
            ],
            recommendations=[
                "Set an account session duration of " + str(MAX_SESSION_SECONDS) +
                " seconds (24 hours) or less in claude.ai > Organization settings."
            ],
            input_summary={"settingsReported": settings_count, "sessionDurationSeconds": None},
            metadata=METADATA,
        )

    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return create_response(
            result={"isSessionDurationLimited": False, "sessionDurationSeconds": None,
                    "maxAllowedSeconds": MAX_SESSION_SECONDS},
            validation=validation,
            fail_reasons=["Unexpected account_session_duration_seconds value: " + repr(raw) + "."],
            recommendations=["Report this to the Spektrum integrations team; the API contract may have changed."],
            input_summary={"settingsReported": settings_count},
            metadata=METADATA,
        )

    seconds = int(raw)
    result = 0 < seconds <= MAX_SESSION_SECONDS
    hours = round(seconds / 3600.0, 1)

    if result:
        pass_reasons = [
            "Sessions expire after " + str(seconds) + " seconds (" + str(hours) +
            " hours), within the " + str(MAX_SESSION_SECONDS) + " second maximum."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "Sessions last " + str(seconds) + " seconds (" + str(hours) + " hours), which exceeds "
            "the " + str(MAX_SESSION_SECONDS) + " second (24 hour) maximum."
        ]
        recommendations = [
            "Reduce the account session duration to " + str(MAX_SESSION_SECONDS) + " seconds or less."
        ]

    return create_response(
        result={
            "isSessionDurationLimited": result,
            "sessionDurationSeconds": seconds,
            "sessionDurationHours": hours,
            "maxAllowedSeconds": MAX_SESSION_SECONDS,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"settingsReported": settings_count, "sessionDurationSeconds": seconds},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isSessionDurationLimited": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
