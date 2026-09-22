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


ENCRYPTION_FIELD_NAMES = [
    "encrypted",
    "is_encrypted",
    "disk_encrypted",
    "storage_encrypted",
    "encryption_status",
    "device_encrypted",
    "fde_enabled",
    "full_disk_encryption",
]

TRUE_STRINGS = ("true", "yes", "enabled", "encrypted", "secure", "compliant")
FALSE_STRINGS = ("false", "no", "disabled", "unencrypted", "not_encrypted", "non_compliant", "insecure")


def read_encryption_flag(obj):
    if not isinstance(obj, dict):
        return None
    for key in ENCRYPTION_FIELD_NAMES:
        if key in obj:
            value = obj.get(key)
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.lower()
                if lowered in TRUE_STRINGS:
                    return True
                if lowered in FALSE_STRINGS:
                    return False
    return None


def find_device_encryption(device):
    if not isinstance(device, dict):
        return None
    flag = read_encryption_flag(device)
    if flag is not None:
        return flag
    details = device.get("details")
    flag = read_encryption_flag(details)
    if flag is not None:
        return flag
    return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    devices = data.get("devices")
    if not isinstance(devices, list):
        devices = []

    reported_count_field = data.get("count")
    fleet_devices = reported_count_field if isinstance(reported_count_field, int) else len(devices)
    total_devices = len(devices)

    explicit_true = 0
    explicit_false = 0
    explicit_unknown = 0

    proxy_secure = 0
    proxy_insecure = 0
    proxy_unknown = 0

    for device in devices:
        if not isinstance(device, dict):
            explicit_unknown = explicit_unknown + 1
            proxy_unknown = proxy_unknown + 1
            continue
        flag = find_device_encryption(device)
        if flag is True:
            explicit_true = explicit_true + 1
        elif flag is False:
            explicit_false = explicit_false + 1
        else:
            explicit_unknown = explicit_unknown + 1

        security_status = device.get("security_status")
        protection_status = device.get("protection_status")
        if security_status == "SECURE" and protection_status == "PROTECTED":
            proxy_secure = proxy_secure + 1
        elif security_status is not None or protection_status is not None:
            proxy_insecure = proxy_insecure + 1
        else:
            proxy_unknown = proxy_unknown + 1

    explicit_found = explicit_true + explicit_false

    input_summary = {
        "totalDevices": fleet_devices,
        "sampledDevices": total_devices,
        "explicitEncryptionFieldFound": explicit_found,
        "explicitEncryptedCount": explicit_true,
        "explicitUnencryptedCount": explicit_false,
        "proxySecureAndProtectedCount": proxy_secure,
        "proxyNotSecureOrNotProtectedCount": proxy_insecure,
        "proxyUnknownCount": proxy_unknown,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        result = {"isDeviceEncrypted": False, "totalDevices": fleet_devices, "sampledDevices": total_devices}
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No devices were returned by getDevices; encryption state cannot be confirmed for any device."],
            recommendations=["Verify the Lookout tenant has enrolled devices and that the API credential has access to the device inventory."],
            input_summary=input_summary,
            metadata={"transformationId": "isDeviceEncrypted", "vendor": "Lookout", "category": "mobile-security"},
        )

    if explicit_found > 0:
        is_encrypted = explicit_false == 0
        if is_encrypted:
            pass_reasons.append(
                f"All {explicit_found} of {total_devices} devices in this response with a reported encryption field show it as encrypted (explicitEncryptedCount={explicit_true})."
            )
        else:
            fail_reasons.append(
                f"{explicit_false} of {explicit_found} devices with a reported encryption field are NOT encrypted (explicitUnencryptedCount={explicit_false}, explicitEncryptedCount={explicit_true})."
            )
            recommendations.append(
                "Enforce device-level storage encryption (e.g. via MDM policy) on the devices flagged as unencrypted and re-scan."
            )
        result = {
            "isDeviceEncrypted": is_encrypted,
            "totalDevices": fleet_devices,
            "sampledDevices": total_devices,
            "explicitEncryptedCount": explicit_true,
            "explicitUnencryptedCount": explicit_false,
        }
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            metadata={"transformationId": "isDeviceEncrypted", "vendor": "Lookout", "category": "mobile-security"},
        )

    # No explicit encryption field observed anywhere in this page of devices.
    # Fall back to Lookout's device threat protection posture (security_status=="SECURE"
    # and protection_status=="PROTECTED") as the closest available proxy for the device
    # being fully compliant with the threat-protection module, which Lookout ties
    # encryption enforcement checks into.
    is_encrypted = proxy_secure > 0 and proxy_insecure == 0
    if is_encrypted:
        pass_reasons.append(
            f"No explicit encryption field was present, but {proxy_secure} of {total_devices} devices report security_status=SECURE and protection_status=PROTECTED, "
            "the closest available signal from Lookout's device threat protection module."
        )
    else:
        fail_reasons.append(
            f"No explicit encryption field was present, and {proxy_insecure} of {total_devices} devices do not report both security_status=SECURE and protection_status=PROTECTED "
            f"(proxySecureAndProtectedCount={proxy_secure}, proxyNotSecureOrNotProtectedCount={proxy_insecure}, proxyUnknownCount={proxy_unknown})."
        )
        recommendations.append(
            "Investigate devices not reporting SECURE/PROTECTED status in Lookout and confirm their storage encryption state directly with the device MDM."
        )

    result = {
        "isDeviceEncrypted": is_encrypted,
        "totalDevices": fleet_devices,
        "sampledDevices": total_devices,
        "proxySecureAndProtectedCount": proxy_secure,
        "proxyNotSecureOrNotProtectedCount": proxy_insecure,
    }
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isDeviceEncrypted", "vendor": "Lookout", "category": "mobile-security"},
    )
