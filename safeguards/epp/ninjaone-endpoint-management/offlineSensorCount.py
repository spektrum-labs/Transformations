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


def normalize_devices(data):
    """Normalize getDevicesDetailed responses into a list of device dict records.

    Handles three observed shapes:
      1. Canonical list-of-records under 'data': {"data": [{...}, ...]}
      2. Columnar/parallel-array shape (seen in tenant capture):
         {"id": [...], "offline": [...], "organizationId": [...], ...}
      3. A bare list of records.
    """
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]

    if not isinstance(data, dict):
        return []

    maybe_list = data.get("data")
    if isinstance(maybe_list, list) and (len(maybe_list) == 0 or isinstance(maybe_list[0], dict)):
        return [r for r in maybe_list if isinstance(r, dict)]

    offline_col = data.get("offline")
    if isinstance(offline_col, list):
        id_col = data.get("id") if isinstance(data.get("id"), list) else []
        records = []
        n = len(offline_col)
        i = 0
        while i < n:
            rec = {"offline": offline_col[i]}
            if i < len(id_col):
                rec["id"] = id_col[i]
            records.append(rec)
            i = i + 1
        return records

    return []


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    devices = normalize_devices(data)
    total_devices = len(devices)
    offline_devices = [d for d in devices if d.get("offline") is True]
    offline_count = len(offline_devices)

    if total_devices == 0:
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = ["No device records were present in the getDevicesDetailed response to evaluate."]
    else:
        pass_reasons = [
            f"Counted {offline_count} of {total_devices} devices reporting offline=true in getDevicesDetailed."
        ]
        fail_reasons = []
        recommendations = []
        if offline_count > 0:
            recommendations = [
                "Investigate the offline devices for connectivity or agent health issues; consider automated re-enrollment or hardware checks for devices offline beyond a normal maintenance window."
            ]
        additional_findings = []

    result = {
        "offlineSensorCount": offline_count,
        "totalDevices": total_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total_devices, "offlineDevices": offline_count},
        additional_findings=additional_findings,
        metadata={
            "transformationId": "offlineSensorCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
