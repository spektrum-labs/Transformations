
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


EDR_KEYWORDS = [
    "edr",
    "endpoint defense",
    "crowdstrike",
    "sentinelone",
    "defender for endpoint",
    "carbon black",
    "cortex",
    "xdr",
    "cylance",
    "cybereason",
]


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

    total_devices = set()
    edr_devices = set()
    edr_product_names = set()
    non_edr_devices = set()

    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        if device_id is not None:
            total_devices.add(device_id)
        product_name = rec.get("productName") or ""
        product_name_lower = product_name.lower()
        is_edr_product = False
        for kw in EDR_KEYWORDS:
            if kw in product_name_lower:
                is_edr_product = True
                break
        if is_edr_product:
            if device_id is not None:
                edr_devices.add(device_id)
            edr_product_names.add(product_name)
        else:
            if device_id is not None and product_name and product_name != "NONE":
                non_edr_devices.add(device_id)

    total_device_count = len(total_devices)
    edr_device_count = len(edr_devices)
    is_edr_deployed = edr_device_count > 0

    input_summary = {
        "totalDevicesInReport": total_device_count,
        "edrCapableDeviceCount": edr_device_count,
        "edrProductNamesFound": sorted(list(edr_product_names)),
    }

    if is_edr_deployed:
        pass_reasons = [
            f"Found {edr_device_count} of {total_device_count} reporting devices with an "
            f"EDR-capable product installed (productName values: {sorted(list(edr_product_names))}).",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_device_count} devices in the antivirus status report report an "
            f"EDR-capable productName; only traditional AV products or 'NONE' were observed.",
        ]
        recommendations = [
            "Deploy an EDR-capable agent (native NinjaOne EDR integration or a supported third-party "
            "EDR product such as CrowdStrike, SentinelOne, or Sophos Endpoint Defense) to managed devices.",
        ]

    result = {
        "isEDRDeployed": is_edr_deployed,
        "totalDevices": total_device_count,
        "edrDeviceCount": edr_device_count,
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
            "vendor": "NinjaOne Endpoint management",
            "category": "epp",
        },
    )
