"""
Transformation: isDirectorySyncEnabled
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures organization membership is provisioned and deprovisioned by the identity provider through SCIM directory sync, rather than by manual invitation.
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
    "transformationId": "isDirectorySyncEnabled",
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


SCIM_MODES = ("scim_advanced", "scim_permissive")
JIT_MODES = ("jit_advanced", "jit_permissive")


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    settings = _settings_map(data)
    settings_count = len(settings)
    sync_raw = settings.get("directory_sync_enabled", _MISSING)
    mode_raw = settings.get("sso_provisioning_mode", _MISSING)

    if sync_raw is _MISSING and mode_raw is _MISSING:
        return create_response(
            result={"isDirectorySyncEnabled": False, "directorySyncEnabled": None, "provisioningMode": None},
            validation=validation,
            fail_reasons=[
                "Neither 'directory_sync_enabled' nor 'sso_provisioning_mode' was reported, so "
                "identity-provider provisioning cannot be proven for this organization."
            ],
            recommendations=["Confirm the organization's plan supports SCIM directory sync."],
            input_summary={"settingsReported": settings_count, "settingPresent": False},
            metadata=METADATA,
        )

    sync_on = sync_raw is not _MISSING and _as_bool(sync_raw)
    mode = mode_raw if mode_raw is not _MISSING else None
    is_scim = isinstance(mode, str) and mode in SCIM_MODES
    result = sync_on and is_scim

    if result:
        pass_reasons = [
            "Directory sync is enabled and the enforced provisioning mode is '" + str(mode) +
            "', so joiner, mover and leaver changes flow from the identity provider."
        ]
        fail_reasons = []
        recommendations = []
    elif not sync_on:
        pass_reasons = []
        fail_reasons = [
            "Directory sync is off (directory_sync_enabled is false), so membership is not "
            "driven by the identity provider and departures are not deprovisioned automatically."
        ]
        recommendations = ["Enable SCIM directory sync in claude.ai > Organization settings."]
    elif isinstance(mode, str) and mode in JIT_MODES:
        pass_reasons = []
        fail_reasons = [
            "The enforced provisioning mode is '" + str(mode) + "'. Just-in-time provisioning "
            "creates users on first login but does not remove them when they leave the identity "
            "provider, so the leaver half of the control is unproven."
        ]
        recommendations = ["Move from just-in-time to SCIM provisioning so deprovisioning is automatic."]
    else:
        pass_reasons = []
        fail_reasons = [
            "Directory sync is on but the enforced provisioning mode is '" + str(mode) +
            "' rather than a SCIM mode. Anthropic reports a configured mode only while the "
            "mechanism enforcing it is active."
        ]
        recommendations = ["Configure SCIM provisioning in the identity provider and re-check."]

    return create_response(
        result={
            "isDirectorySyncEnabled": result,
            "directorySyncEnabled": sync_on,
            "provisioningMode": mode,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"settingsReported": settings_count, "provisioningMode": mode},
        metadata=METADATA,
    )


def transform(input):
    try:
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isDirectorySyncEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
