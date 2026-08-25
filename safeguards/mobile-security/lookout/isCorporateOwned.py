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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}
    devices = data.get("devices") or []
    if not isinstance(devices, list):
        devices = []

    candidate_keys = [
        "ownership", "device_ownership", "owner_type", "ownershipType",
        "corporate_owned", "is_corporate_owned", "byod", "is_byod",
        "ownership_type", "owner_type_name",
    ]
    negative_keys = ["byod", "is_byod"]

    corporate_count = 0
    personal_count = 0
    unknown_count = 0
    sample_corporate = []
    sample_personal = []

    for d in devices:
        if not isinstance(d, dict):
            unknown_count = unknown_count + 1
            continue
        val = None
        found_key = None
        for k in candidate_keys:
            if k in d:
                val = d.get(k)
                found_key = k
                break
        if val is None:
            details = d.get("details") or {}
            if isinstance(details, dict):
                for k in candidate_keys:
                    if k in details:
                        val = details.get(k)
                        found_key = k
                        break

        if val is None:
            unknown_count = unknown_count + 1
            continue

        is_corp = None
        if isinstance(val, bool):
            if found_key in negative_keys:
                is_corp = not val
            else:
                is_corp = val
        else:
            sval = str(val).strip().lower()
            if sval in ("corporate", "corp", "company", "company-owned", "company_owned", "org", "organization"):
                is_corp = True
            elif sval in ("personal", "byod", "employee", "employee-owned", "own"):
                is_corp = False
            elif sval in ("true", "yes", "1") and found_key not in negative_keys:
                is_corp = True
            elif sval in ("false", "no", "0") and found_key not in negative_keys:
                is_corp = False
            elif sval in ("true", "yes", "1") and found_key in negative_keys:
                is_corp = False
            elif sval in ("false", "no", "0") and found_key in negative_keys:
                is_corp = True
            else:
                is_corp = None

        if is_corp is True:
            corporate_count = corporate_count + 1
            if len(sample_corporate) < 3:
                sample_corporate.append(d.get("guid", "unknown"))
        elif is_corp is False:
            personal_count = personal_count + 1
            if len(sample_personal) < 3:
                sample_personal.append(d.get("guid", "unknown"))
        else:
            unknown_count = unknown_count + 1

    total_devices = len(devices)
    classified = corporate_count + personal_count

    if classified > 0:
        is_corporate_owned = corporate_count > personal_count
    else:
        is_corporate_owned = False

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if classified == 0:
        fail_reasons.append(
            f"None of the {total_devices} device records in this response exposed an ownership field "
            f"(checked keys: ownership, device_ownership, owner_type, byod and nested details) so ownership "
            f"could not be confirmed from Lookout's device data."
        )
        recommendations.append(
            "Verify the connected MDM is passing device ownership metadata (e.g. ownership/owner_type) "
            "through to Lookout so it appears in the devices endpoint response."
        )
    elif is_corporate_owned:
        pass_reasons.append(
            f"{corporate_count} of {classified} devices with a resolvable ownership field report corporate "
            f"ownership (sample guids: {sample_corporate}), versus {personal_count} personal/BYOD devices."
        )
    else:
        fail_reasons.append(
            f"Only {corporate_count} of {classified} devices with a resolvable ownership field report corporate "
            f"ownership, while {personal_count} are personal/BYOD (sample guids: {sample_personal})."
        )
        recommendations.append(
            "Review MDM enrollment policy: a majority of tracked devices are personal/BYOD rather than "
            "corporate-owned."
        )

    result = {
        "isCorporateOwned": is_corporate_owned,
        "totalDevices": total_devices,
        "corporateDevices": corporate_count,
        "personalDevices": personal_count,
        "unknownOwnershipDevices": unknown_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDevices": total_devices,
            "classifiedDevices": classified,
            "corporateDevices": corporate_count,
            "personalDevices": personal_count,
            "unknownOwnershipDevices": unknown_count,
        },
        metadata={
            "transformationId": "isCorporateOwned",
            "vendor": "Lookout",
            "category": "mobile-security",
        },
    )
