
import json
from datetime import datetime


def extract_input(input_data):
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


def b64index(c, alphabet):
    idx = 0
    found = False
    pos = 0
    for a in alphabet:
        if a == c:
            idx = pos
            found = True
            break
        pos = pos + 1
    return idx if found else -1


def tobits(value, width):
    bits = ""
    i = width - 1
    while i >= 0:
        bit = (value >> i) & 1
        bits = bits + str(bit)
        i = i - 1
    return bits


def b64decode(s):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    s = s.strip()
    s = s.rstrip("=")
    bits = ""
    for c in s:
        idx = b64index(c, alphabet)
        if idx < 0:
            continue
        bits = bits + tobits(idx, 6)
    usable_len = (len(bits) // 8) * 8
    bits = bits[:usable_len]
    out_chars = []
    i = 0
    while i < len(bits):
        byte_bits = bits[i:i + 8]
        value = int(byte_bits, 2)
        out_chars.append(chr(value))
        i = i + 8
    return "".join(out_chars)


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    api_errors = []
    transformation_errors = []

    configuration_id = None
    if isinstance(data, dict):
        configuration_id = data.get("configuration_id")

    decoded_json = None
    private_encryption_enabled = False
    encryption_required = None
    desktop_app_status = None

    if configuration_id:
        try:
            decoded_str = b64decode(configuration_id)
            decoded_json = json.loads(decoded_str)
        except Exception as e:
            transformation_errors.append(f"Failed to decode/parse configuration_id: {e}")
            decoded_json = None
    else:
        transformation_errors.append("No configuration_id present in response")

    if isinstance(decoded_json, dict):
        encryption_required = decoded_json.get("encryptionRequired")
        desktop_app_status = decoded_json.get("desktopAppStatus")
        private_encryption_enabled = bool(encryption_required)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if decoded_json is None:
        fail_reasons.append(
            "Could not decode configuration_id to determine encryption configuration."
        )
        recommendations.append(
            "Verify the company has a valid configuration_id and re-check the fetch_config_id endpoint."
        )
    elif private_encryption_enabled:
        pass_reasons.append(
            f"Decoded configuration_id token reports encryptionRequired={encryption_required}, "
            "indicating client configurations for this company are generated with private "
            "(user-controlled) encryption required."
        )
    else:
        fail_reasons.append(
            f"Decoded configuration_id token reports encryptionRequired={encryption_required}, "
            "indicating the company's default client configuration does NOT require a "
            "private/user-controlled encryption key (IDrive's default key is used instead)."
        )
        recommendations.append(
            "Regenerate the company's client configuration with the private_encryption "
            "parameter enabled so new device installs use a user-controlled encryption key."
        )

    result = {
        "isPrivateEncryptionKeyEnabled": private_encryption_enabled,
        "encryptionRequired": encryption_required,
        "desktopAppStatus": desktop_app_status,
    }

    input_summary = {
        "configurationIdPresent": bool(configuration_id),
        "decodedSuccessfully": decoded_json is not None,
        "encryptionRequired": encryption_required,
    }

    metadata = {
        "transformationId": "isPrivateEncryptionKeyEnabled",
        "vendor": "IDrive",
        "category": "backup",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
        transformation_errors=transformation_errors,
        api_errors=api_errors,
    )
