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


EDR_PRODUCT_MARKERS = [
    "crowdstrike",
    "sentinelone",
    "sentinel one",
    "bitdefender",
    "carbon black",
    "cortex xdr",
    "cylance",
    "intercept x",
    "sophos",
    "trend micro",
    "symantec endpoint",
    "mvision",
    "fireeye",
    "elastic endpoint",
    "deep instinct",
    "huntress",
    "cybereason",
    "tanium",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
        if not isinstance(results, list):
            results = []
    else:
        results = []

    edr_products_found = []
    edr_device_ids = set()
    total_records = 0

    for rec in results:
        if not isinstance(rec, dict):
            continue
        total_records = total_records + 1
        name = rec.get("productName") or ""
        name_lower = name.lower()
        is_edr = False
        for marker in EDR_PRODUCT_MARKERS:
            if marker in name_lower:
                is_edr = True
                break
        if is_edr:
            if name not in edr_products_found:
                edr_products_found.append(name)
            device_id = rec.get("deviceId")
            if device_id is not None:
                edr_device_ids.add(device_id)

    is_edr_deployed = len(edr_device_ids) > 0

    input_summary = {
        "totalAntivirusStatusRecords": total_records,
        "edrProductsFound": edr_products_found,
        "edrDeviceCount": len(edr_device_ids),
    }

    if is_edr_deployed:
        pass_reasons = [
            "Antivirus status report shows " + str(len(edr_device_ids)) +
            " device(s) reporting a third-party EDR product ("
            + ", ".join(edr_products_found) + ") via productName in /v2/queries/antivirus-status results."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "None of the " + str(total_records) +
            " antivirus-status records reported a recognized third-party EDR productName "
            "(only Microsoft Defender Antivirus or no matching EDR marker were found)."
        ]
        recommendations = [
            "Deploy and enroll a third-party EDR agent (e.g. CrowdStrike Falcon, SentinelOne, Bitdefender) "
            "on managed endpoints so it reports through the NinjaOne antivirus-status integration."
        ]

    result = {
        "isEDRDeployed": is_edr_deployed,
        "edrDeviceCount": len(edr_device_ids),
        "edrProductsFound": edr_products_found,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEDRDeployed",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
