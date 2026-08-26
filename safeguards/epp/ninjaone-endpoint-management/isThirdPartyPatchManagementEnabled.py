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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
    else:
        results = []

    if not isinstance(results, list):
        results = []

    total_records = len(results)

    installed_statuses = set(["INSTALLED", "SUCCESS", "COMPLETED"])
    installed_count = 0
    device_ids = set()
    sample_titles = []
    for rec in results:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        if device_id is not None:
            device_ids.add(device_id)
        status = rec.get("status")
        if isinstance(status, str) and status.upper() in installed_statuses:
            installed_count = installed_count + 1
            if len(sample_titles) < 5:
                title = rec.get("title") or rec.get("productIdentifier") or "unknown"
                sample_titles.append(title)

    is_enabled = installed_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        sample_str = ", ".join([str(t) for t in sample_titles])
        pass_reasons.append(
            f"Software patch installs report returned {installed_count} installed third-party "
            f"patch records across {len(device_ids)} devices (sample titles: {sample_str}), "
            f"confirming third-party patch management is active."
        )
    else:
        fail_reasons.append(
            f"Software patch installs report (getSoftwarePatchInstallsReport) returned "
            f"{total_records} total records and 0 records with an installed status, "
            f"indicating no third-party patch installation activity is currently tracked."
        )
        recommendations.append(
            "Enable and configure third-party software patch management policies in NinjaOne "
            "so that browser/Java/Adobe and other third-party application patches are scanned "
            "for and installed, then verify installs appear in the software-patch-installs report."
        )

    result = {
        "isThirdPartyPatchManagementEnabled": is_enabled,
        "totalPatchInstallRecords": total_records,
        "installedPatchCount": installed_count,
        "devicesWithInstalls": len(device_ids),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPatchInstallRecords": total_records,
            "installedPatchCount": installed_count,
        },
        metadata={
            "transformationId": "isThirdPartyPatchManagementEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
