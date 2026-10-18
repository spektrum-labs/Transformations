
import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isBackupEncrypted',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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


B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64decode_to_str(s):
    if not s or not isinstance(s, str):
        return ""
    s = s.strip()
    if s.endswith("=="):
        s = s[:-2]
    elif s.endswith("="):
        s = s[:-1]
    bits = ""
    for ch in s:
        idx = B64_ALPHABET.find(ch)
        if idx < 0:
            continue
        b = ""
        n = idx
        for i in range(6):
            b = str(n % 2) + b
            n = n // 2
        bits = bits + b
    usable_len = len(bits) - (len(bits) % 8)
    chars = []
    i = 0
    while i < usable_len:
        byte = bits[i:i + 8]
        val = int(byte, 2)
        chars.append(chr(val))
        i = i + 8
    return "".join(chars)


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        record = data[0] if len(data) > 0 else {}
    else:
        record = data

    if not isinstance(record, dict):
        record = {}

    config_id_b64 = record.get("configuration_id") or ""
    company_name = record.get("name") or "unknown company"

    decoded_json = None
    decode_error = None
    if config_id_b64:
        try:
            decoded_str = b64decode_to_str(config_id_b64)
            decoded_json = json.loads(decoded_str)
        except Exception as e:
            decode_error = str(e)

    transformation_errors = []
    if decode_error:
        transformation_errors.append(f"Failed to decode configuration_id: {decode_error}")

    encryption_required = None
    if isinstance(decoded_json, dict):
        encryption_required = decoded_json.get("encryptionRequired")

    # IDrive 360 encrypts every backup with AES-256 on transfer and storage; the only
    # choice is the key: the default key (IDrive-managed) or a private key known only to
    # the customer (https://www.idrive360.com/help/360/Backup/encryption_key.htm). The
    # decoded configuration_id therefore states the key mode, not whether backups are
    # encrypted: encryptionRequired=false is the default key, still AES-256. Private-key
    # enforcement is judged separately by isPrivateKeyEncryptionEnforced.
    # No readable flag is no evidence, so the result is None (fail closed), never True.
    if encryption_required is True:
        is_backup_encrypted = True
        pass_reasons = [
            f"Company '{company_name}' configuration_id decodes to encryptionRequired=true: "
            f"backups are AES-256 encrypted with a private encryption key."
        ]
        fail_reasons = []
        recommendations = []
    elif encryption_required is False:
        is_backup_encrypted = True
        pass_reasons = [
            f"Company '{company_name}' configuration_id decodes to encryptionRequired=false: "
            f"backups are AES-256 encrypted with the IDrive 360 default key (private key not required)."
        ]
        fail_reasons = []
        recommendations = [
            "For customer-held keys, require private-key encryption when generating client "
            "configuration IDs (see isPrivateKeyEncryptionEnforced)."
        ]
    else:
        is_backup_encrypted = None
        pass_reasons = []
        fail_reasons = [
            f"Could not determine the encryption mode for company '{company_name}'; "
            f"configuration_id was missing, empty, or failed to decode."
        ]
        recommendations = [
            "Verify the /company or /company/fetch_config_id endpoint returns a valid "
            "configuration_id token for this company."
        ]
        transformation_errors.append("encryptionRequired flag not found in decoded configuration_id")

    input_summary = {
        "companyName": company_name,
        "hasConfigurationId": bool(config_id_b64),
        "encryptionRequired": encryption_required,
    }

    return create_response(
        result={"isBackupEncrypted": is_backup_encrypted},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "isBackupEncrypted",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
