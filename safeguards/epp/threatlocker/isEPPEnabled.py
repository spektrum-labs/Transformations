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


# ThreatLocker's confirmed "Mode" values (threatlocker.kb.help/portalapicomputer/):
# Secure, Installation, Learning, Monitor Only, Elevation Mode. Only "Secure" means
# Application Control is actively enforced rather than just observing/logging.
SECURE_MODE_VALUES = {"secure"}

# The exact JSON field names ComputerGetByAllParameters returns were not published
# in the fetched vendor docs (only the filterable concepts "Mode" and "Machine State"
# were confirmed) — this tries the plausible variants defensively rather than
# assuming one casing, the same way the Datto backup transformations in this repo
# tolerate multiple vendor response shapes.
MODE_FIELD_CANDIDATES = ["mode", "Mode", "computerMode", "protectionMode"]
NAME_FIELD_CANDIDATES = ["computerName", "ComputerName", "name", "hostname"]


def _first_present(d, candidates):
    for key in candidates:
        if isinstance(d, dict) and key in d and d[key] is not None:
            return d[key]
    return None


def _extract_computers(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["items", "data", "computers", "rows", "results"]:
            val = data.get(key)
            if isinstance(val, list):
                return val
    return []


def transform(input):
    data, validation = extract_input(input)

    api_errors = []
    if isinstance(data, dict) and data.get("error"):
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    computers = _extract_computers(data)

    total = len(computers)
    secure = []
    not_secure = []
    unknown_mode = []

    for c in computers:
        if not isinstance(c, dict):
            continue
        mode = _first_present(c, MODE_FIELD_CANDIDATES)
        name = _first_present(c, NAME_FIELD_CANDIDATES) or "unknown"
        if mode is None:
            unknown_mode.append(name)
            continue
        if str(mode).strip().lower() in SECURE_MODE_VALUES:
            secure.append(name)
        else:
            not_secure.append((name, mode))

    is_epp_enabled = total > 0 and len(secure) == total

    input_summary = {
        "totalComputers": total,
        "secureModeComputers": len(secure),
        "notSecureModeComputers": len(not_secure),
        "unknownModeComputers": len(unknown_mode),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append("No managed computers were returned by ThreatLocker; cannot confirm enforcement.")
        recommendations.append("Confirm the Managed Organization Id is correct and that computers are enrolled in this ThreatLocker organization.")
    elif unknown_mode and not not_secure and len(secure) + len(unknown_mode) == total:
        fail_reasons.append(
            "Could not determine the enforcement mode for %d of %d computers (e.g. %s) — the response did not carry a recognized mode field."
            % (len(unknown_mode), total, ", ".join(unknown_mode[:5]))
        )
        recommendations.append("Confirm the exact field name ThreatLocker returns for computer mode and update this transformation's MODE_FIELD_CANDIDATES.")
    elif is_epp_enabled:
        pass_reasons.append("All %d managed computers are in Secure Mode." % total)
    else:
        names = ", ".join(["%s (%s)" % (n, m) for n, m in not_secure[:5]])
        fail_reasons.append(
            "%d of %d managed computers are not in Secure Mode (e.g. %s), meaning Application Control is not actively enforced on those machines."
            % (len(not_secure), total, names)
        )
        recommendations.append("Move all managed computers into Secure Mode (out of Learning/Monitor Only/Installation) once policies have been tuned.")

    result = {
        "isEPPEnabled": is_epp_enabled,
        "totalComputers": total,
        "secureModeComputers": len(secure),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "ThreatLocker",
            "category": "epp",
        },
    )
