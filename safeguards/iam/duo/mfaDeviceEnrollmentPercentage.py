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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        users = data
    elif isinstance(data, dict):
        users = data.get("response") or data.get("data") or []
        if not isinstance(users, list):
            users = []
    else:
        users = []

    inactive_statuses = ("disabled", "locked out", "deleted")

    total_active = 0
    active_with_device = 0
    unknown_device_signal = 0

    for u in users:
        if not isinstance(u, dict):
            continue
        # Skip pure truncation-marker stub entries with no real user fields
        if "_truncated" in u and len(u.keys()) == 1:
            continue

        status_raw = u.get("status")
        is_known_inactive = False
        if status_raw:
            if str(status_raw).lower() in inactive_statuses:
                is_known_inactive = True
        if is_known_inactive:
            continue

        total_active = total_active + 1

        has_device = False
        has_any_signal = False

        if "is_enrolled" in u:
            has_any_signal = True
            if u.get("is_enrolled"):
                has_device = True

        for field in ("phones", "tokens", "u2ftokens", "webauthncredentials", "desktop_authenticators"):
            if field in u:
                has_any_signal = True
                val = u.get(field) or []
                if isinstance(val, list) and len(val) > 0:
                    has_device = True

        if not has_any_signal:
            unknown_device_signal = unknown_device_signal + 1

        if has_device:
            active_with_device = active_with_device + 1

    percentage = 0.0
    if total_active > 0:
        percentage = round((active_with_device / total_active) * 100, 2)

    validation_errors = []
    if total_active == 0:
        validation_errors.append("No active users found in response - cannot compute enrollment percentage")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_active > 0:
        if active_with_device == total_active:
            pass_reasons.append(
                f"All {total_active} active Duo users have at least one enrolled authentication device "
                f"(is_enrolled=true or a non-empty phones/tokens/u2ftokens/webauthncredentials/desktop_authenticators array)."
            )
        elif active_with_device > 0:
            pass_reasons.append(
                f"{active_with_device} of {total_active} active Duo users ({percentage}%) have at least one "
                f"enrolled authentication device."
            )
        if active_with_device < total_active:
            missing = total_active - active_with_device
            fail_reasons.append(
                f"{missing} of {total_active} active Duo users show no enrolled authentication device "
                f"(is_enrolled=false/absent and empty phones/tokens/u2ftokens/webauthncredentials/desktop_authenticators)."
            )
            recommendations.append(
                "Prompt the users lacking an enrolled MFA device to complete Duo enrollment "
                "(phone, hardware token, or WebAuthn/U2F key) before their next authentication."
            )
        if unknown_device_signal > 0:
            fail_reasons.append(
                f"{unknown_device_signal} of {total_active} active users had no device-related fields present in "
                f"the response payload at all (truncated/partial record), so their enrollment status could not be confirmed."
            )
    else:
        fail_reasons.append("No active users were found in the Duo user list; enrollment percentage could not be computed.")
        recommendations.append("Verify the getUsers API call is returning the tenant's active user population.")

    result = {
        "mfaDeviceEnrollmentPercentage": percentage,
        "activeUsers": total_active,
        "usersWithEnrolledDevice": active_with_device,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"activeUsers": total_active, "usersWithEnrolledDevice": active_with_device, "unknownDeviceSignal": unknown_device_signal},
        transformation_errors=validation_errors if total_active == 0 else [],
        metadata={
            "transformationId": "mfaDeviceEnrollmentPercentage",
            "vendor": "Duo",
            "category": "iam",
        },
    )
