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
    partitions = data.get("data") or []
    if not isinstance(partitions, list):
        partitions = []

    total_partitions = len(partitions)
    forwarded_partitions = [
        p for p in partitions
        if isinstance(p, dict) and p.get("dataForwardingId")
    ]
    forwarded_count = len(forwarded_partitions)
    is_configured = forwarded_count > 0

    if is_configured:
        names = [p.get("name") for p in forwarded_partitions][:5]
        pass_reasons = [
            f"{forwarded_count} of {total_partitions} partitions have a non-null dataForwardingId "
            f"(examples: {names}), indicating log data is being forwarded to an external SIEM destination."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_partitions} partitions returned by /api/v1/partitions have a "
            "populated dataForwardingId, so no Data Forwarding (SIEM export) destination is configured."
        ]
        recommendations = [
            "Configure Data Forwarding on at least one partition (e.g. sumologic_default) to continuously "
            "export indexed log data to an external SIEM destination such as S3, then verify dataForwardingId "
            "is populated."
        ]

    result = {
        "isSIEMForwardingConfigured": is_configured,
        "totalPartitions": total_partitions,
        "forwardingConfiguredPartitions": forwarded_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalPartitions": total_partitions, "forwardedPartitions": forwarded_count},
        metadata={
            "transformationId": "isSIEMForwardingConfigured",
            "vendor": "Sumo Logic Continuous Intelligence Service",
            "category": "incidentmgmt",
        },
    )
