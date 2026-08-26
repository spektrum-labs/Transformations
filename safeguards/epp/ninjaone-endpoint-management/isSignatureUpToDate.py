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

    total_records = 0
    out_of_date_records = 0
    up_to_date_records = 0
    out_of_date_samples = []

    for rec in results:
        if not isinstance(rec, dict):
            continue
        # skip cursor-only wrapper items (e.g. from getAlerts-like shape)
        if "definitionStatus" not in rec:
            continue
        total_records = total_records + 1
        status = rec.get("definitionStatus") or ""
        status_norm = status.strip().lower()
        if status_norm == "up-to-date" or status_norm == "up to date":
            up_to_date_records = up_to_date_records + 1
        else:
            out_of_date_records = out_of_date_records + 1
            if len(out_of_date_samples) < 5:
                out_of_date_samples.append({
                    "deviceId": rec.get("deviceId"),
                    "productName": rec.get("productName"),
                    "definitionStatus": status,
                })

    is_up_to_date = total_records > 0 and out_of_date_records == 0

    input_summary = {
        "totalDefinitionRecords": total_records,
        "upToDateRecords": up_to_date_records,
        "outOfDateRecords": out_of_date_records,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_records == 0:
        fail_reasons.append(
            "No antivirus-status records with a definitionStatus field were returned; "
            "signature currency could not be confirmed."
        )
        recommendations.append(
            "Verify the Antivirus Status report is populated for enrolled devices and re-run the scan."
        )
    elif is_up_to_date:
        pass_reasons.append(
            f"All {total_records} antivirus-status records report definitionStatus='Up-to-Date' "
            f"({up_to_date_records} up-to-date, {out_of_date_records} out-of-date)."
        )
    else:
        sample_desc = ", ".join(
            f"device {s.get('deviceId')} ({s.get('productName')}: {s.get('definitionStatus')})"
            for s in out_of_date_samples
        )
        fail_reasons.append(
            f"{out_of_date_records} of {total_records} antivirus-status records report a "
            f"non-'Up-to-Date' definitionStatus, e.g. {sample_desc}."
        )
        recommendations.append(
            "Force a signature/definition update on the affected devices or verify network "
            "connectivity to the AV vendor's update servers."
        )

    result = {
        "isSignatureUpToDate": is_up_to_date,
        "totalDefinitionRecords": total_records,
        "outOfDateRecords": out_of_date_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSignatureUpToDate",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
