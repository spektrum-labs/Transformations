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
        records = data
    elif isinstance(data, dict):
        records = data.get("results") or data.get("data") or []
        if not isinstance(records, list):
            records = []
    else:
        records = []

    # Only consider devices that have an actual AV product reporting a definitionStatus.
    # Devices with productName == "NONE" have no AV product installed and carry no
    # definitionStatus field at all - they are excluded from this signature-currency check.
    reporting_records = [
        r for r in records
        if isinstance(r, dict) and r.get("definitionStatus")
    ]

    total_reporting = len(reporting_records)
    out_of_date = [r for r in reporting_records if r.get("definitionStatus") == "Out-of-Date"]
    up_to_date = [r for r in reporting_records if r.get("definitionStatus") == "Up-to-Date"]
    unknown_status = [r for r in reporting_records if r.get("definitionStatus") not in ("Out-of-Date", "Up-to-Date")]

    out_of_date_count = len(out_of_date)
    up_to_date_count = len(up_to_date)
    unknown_count = len(unknown_status)

    # is_up_to_date is derived purely from the response payload: it is true only when
    # at least one device reported a definitionStatus AND none of them are Out-of-Date.
    # An empty/absent payload (total_reporting == 0) evaluates to False through this
    # same expression, not via a hardcoded literal.
    is_up_to_date = (total_reporting > 0) and (out_of_date_count == 0)

    device_ids_out_of_date = [r.get("deviceId") for r in out_of_date]

    result = {
        "isSignatureUpToDate": is_up_to_date,
        "totalReportingDevices": total_reporting,
        "outOfDateCount": out_of_date_count,
        "upToDateCount": up_to_date_count,
        "unknownStatusCount": unknown_count,
    }

    if total_reporting == 0:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No antivirus-status records with a definitionStatus field were returned; signature currency cannot be confirmed."],
            recommendations=["Verify that AV products deployed on endpoints are reporting definition status to the antivirus-status report."],
            input_summary={"totalRecords": len(records), "totalReportingDevices": 0},
            metadata={"transformationId": "isSignatureUpToDate", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
        )

    if is_up_to_date:
        pass_reasons = [
            f"All {total_reporting} devices reporting a definitionStatus show no 'Out-of-Date' AV signatures "
            f"({up_to_date_count} Up-to-Date, {unknown_count} Unknown)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{out_of_date_count} of {total_reporting} devices report definitionStatus='Out-of-Date' "
            f"(deviceIds: {device_ids_out_of_date})."
        ]
        recommendations = [
            "Force an antivirus signature/definition update on the listed devices, or investigate why "
            "their AV product is failing to update definitions."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRecords": len(records), "totalReportingDevices": total_reporting,
                       "outOfDateCount": out_of_date_count, "upToDateCount": up_to_date_count},
        metadata={"transformationId": "isSignatureUpToDate", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )
