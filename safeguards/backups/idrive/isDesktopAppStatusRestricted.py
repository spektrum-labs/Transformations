
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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def to_bin6(n):
    out = ""
    i = 5
    while i >= 0:
        bit = (n >> i) & 1
        if bit:
            out = out + "1"
        else:
            out = out + "0"
        i = i - 1
    return out


def b64decode_to_text(s):
    if not s:
        return None
    s = s.strip()
    s = s.rstrip("=")
    bits = ""
    for c in s:
        idx = B64_CHARS.find(c)
        if idx < 0:
            return None
        bits = bits + to_bin6(idx)
    n_bytes = len(bits) // 8
    chars = []
    i = 0
    while i < n_bytes:
        chunk = bits[i * 8: i * 8 + 8]
        val = int(chunk, 2)
        chars.append(chr(val))
        i = i + 1
    return "".join(chars)


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        record = data[0] if data else {}
    else:
        record = data

    configuration_id = record.get("configuration_id") if isinstance(record, dict) else None

    decoded_ok = False
    desktop_app_status = None
    decode_error = None

    if configuration_id:
        try:
            decoded_text = b64decode_to_text(configuration_id)
            if decoded_text:
                parsed = json.loads(decoded_text)
                if isinstance(parsed, dict) and "desktopAppStatus" in parsed:
                    desktop_app_status = parsed.get("desktopAppStatus")
                    decoded_ok = True
        except Exception as e:
            decode_error = str(e)

    transformation_errors = []
    if configuration_id and not decoded_ok:
        transformation_errors.append(
            f"Could not decode desktopAppStatus from configuration_id (error: {decode_error})"
        )
    if not configuration_id:
        transformation_errors.append("Missing configuration_id in response")

    # is_restricted is only derived when the token was actually decoded. With no
    # configuration_id, or a configuration_id that failed to decode, there is no
    # evidence of the desktop app's status, so the result is None (no answer)
    # rather than a hardcoded literal or a value derived from a falsy default --
    # that previously made a missing/undecodable token read as "restricted"
    # (the safe/passing answer) via `not bool(None)`.
    is_restricted = None
    if decoded_ok:
        is_restricted = not bool(desktop_app_status)

    if not configuration_id:
        pass_reasons = []
        fail_reasons = ["No configuration_id field found in getConfigurationId response; cannot determine desktop app status from this tenant's data."]
        recommendations = ["Verify the company has a valid configuration_id and that the API token has access to fetch_config_id."]
    elif not decoded_ok:
        pass_reasons = []
        fail_reasons = [f"configuration_id value '{configuration_id}' could not be decoded to extract desktopAppStatus."]
        recommendations = ["Confirm the configuration_id encoding has not changed on the vendor side."]
    elif is_restricted:
        pass_reasons = [
            f"Decoded configuration_id token has desktopAppStatus={desktop_app_status}, indicating the client is provisioned in thin-client mode with end users restricted from changing backup/pause status."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Decoded configuration_id token has desktopAppStatus={desktop_app_status}, indicating full-client features are enabled and end users are NOT restricted from changing the desktop app's backup/pause status."
        ]
        recommendations = [
            "Regenerate the client configuration with full_client=false (private/thin-client mode) so end users cannot pause or change backup status from the desktop app."
        ]

    return create_response(
        result={"isDesktopAppStatusRestricted": is_restricted},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "configuration_id_present": bool(configuration_id),
            "decoded_ok": decoded_ok,
            "desktopAppStatus": desktop_app_status,
        },
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "isDesktopAppStatusRestricted",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
