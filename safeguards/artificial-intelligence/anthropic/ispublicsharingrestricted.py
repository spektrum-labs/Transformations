"""
Transformation: isPublicSharingRestricted
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures organization content cannot be shared publicly through chat sharing, public projects, or integration sharing.
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
    "transformationId": "isPublicSharingRestricted",
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


FLAGS = ('claude_ai_chat_sharing_enabled', 'public_projects_enabled', 'claude_ai_integration_sharing_enabled')


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    settings = _settings_map(data)
    settings_count = len(settings)
    reported = {f: _as_bool(settings[f]) for f in FLAGS if f in settings}
    absent = [f for f in FLAGS if f not in settings]

    if not reported:
        return create_response(
            result={"isPublicSharingRestricted": False, "reportedFlags": [], "absentFlags": absent},
            validation=validation,
            fail_reasons=[
                "None of the settings rows that govern public sharing of organization content (" + ", ".join(FLAGS) +
                ") were returned, so the control cannot be proven. An omitted row means "
                "the organization's administrators cannot change it, not that it is off."
            ],
            recommendations=[
                "Confirm the organization's plan exposes these controls. Disable chat sharing, public projects, and integration sharing in claude.ai > Organization settings."
            ],
            input_summary={"settingsReported": settings_count, "flagsReported": 0},
            metadata=METADATA,
        )

    offenders = sorted(f for f, v in reported.items() if v is not False)
    compliant = sorted(f for f, v in reported.items() if v is False)
    result = not offenders

    if result:
        pass_reasons = [
            "Every reported flag governing public sharing of organization content is disabled (" +
            ", ".join(compliant) + ")."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            str(len(offenders)) + " of " + str(len(reported)) +
            " reported flags governing public sharing of organization content are enabled: " + ", ".join(offenders) + "."
        ]
        recommendations = ["Disable chat sharing, public projects, and integration sharing in claude.ai > Organization settings."]

    findings = []
    if absent:
        findings.append(
            "Not reported for this organization (treated as unprovable, not as compliant): " +
            ", ".join(absent) + "."
        )

    return create_response(
        result={
            "isPublicSharingRestricted": result,
            "reportedFlags": sorted(reported.keys()),
            "offendingFlags": offenders,
            "absentFlags": absent,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=findings,
        input_summary={"settingsReported": settings_count, "flagsReported": len(reported)},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isPublicSharingRestricted": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
