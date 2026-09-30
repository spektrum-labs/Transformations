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


b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def intToBin6(n):
    bits = ""
    i = 5
    while i >= 0:
        bits = bits + str((n >> i) & 1)
        i = i - 1
    return bits


def bin8ToInt(bits8):
    val = 0
    for ch in bits8:
        val = (val << 1) | (1 if ch == "1" else 0)
    return val


def b64decodeToStr(s):
    s = s.strip()
    s = s.rstrip("=")
    bits = ""
    for c in s:
        if c not in b64chars:
            continue
        idx = b64chars.index(c)
        bits = bits + intToBin6(idx)
    usable_len = (len(bits) // 8) * 8
    bits = bits[0:usable_len]
    chars = []
    pos = 0
    while pos < len(bits):
        byte_bits = bits[pos:pos + 8]
        chars.append(chr(bin8ToInt(byte_bits)))
        pos = pos + 8
    return "".join(chars)


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    transformation_errors = []
    fail_reasons = []
    pass_reasons = []
    recommendations = []
    encryption_required = None
    config_id = None
    company_name = None

    if isinstance(data, dict):
        config_id = data.get("configuration_id")
        company_name = data.get("name")
    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        config_id = data[0].get("configuration_id")
        company_name = data[0].get("name")

    decoded_json = None
    if config_id:
        try:
            decoded_str = b64decodeToStr(config_id)
            decoded_json = json.loads(decoded_str)
        except Exception as e:
            transformation_errors.append("Failed to decode/parse configuration_id: %s" % str(e))
    else:
        transformation_errors.append("configuration_id field missing from response")

    if isinstance(decoded_json, dict) and "encryptionRequired" in decoded_json:
        encryption_required = bool(decoded_json.get("encryptionRequired"))

    if encryption_required is True:
        pass_reasons.append(
            "Decoded configuration_id token for company '%s' contains encryptionRequired=true, "
            "meaning newly enrolled devices are provisioned with mandatory encryption." % (company_name or "unknown")
        )
    elif encryption_required is False:
        fail_reasons.append(
            "Decoded configuration_id token for company '%s' contains encryptionRequired=false. "
            "Newly enrolled devices are NOT being provisioned with mandatory encryption." % (company_name or "unknown")
        )
        recommendations.append(
            "Enable the private_encryption / encryption-required option when generating the company's "
            "client configuration so new device enrollments require encryption."
        )
    else:
        fail_reasons.append(
            "Could not determine an encryptionRequired flag from the configuration_id response; "
            "decoded payload was: %s" % str(decoded_json)
        )
        recommendations.append(
            "Verify the company/fetch_config_id endpoint is returning a valid configuration_id token."
        )

    result = {
        "isEncryptionRequiredFlagSet": bool(encryption_required) if encryption_required is not None else False,
    }

    input_summary = {
        "configurationIdPresent": bool(config_id),
        "decodedEncryptionRequired": encryption_required,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "isEncryptionRequiredFlagSet",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
