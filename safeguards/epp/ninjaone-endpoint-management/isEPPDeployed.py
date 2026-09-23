
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

    total_records = len(records)
    deployed_devices = []
    not_deployed_devices = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        product_name = rec.get("productName") or ""
        product_name_clean = product_name.strip().upper() if isinstance(product_name, str) else ""
        if product_name_clean and product_name_clean != "NONE":
            deployed_devices.append(device_id)
        else:
            not_deployed_devices.append(device_id)

    deployed_count = len(deployed_devices)
    not_deployed_count = len(not_deployed_devices)
    is_deployed = deployed_count > 0

    input_summary = {
        "totalDevicesReported": total_records,
        "devicesWithEPPProduct": deployed_count,
        "devicesWithoutEPPProduct": not_deployed_count,
    }

    if is_deployed:
        sample_ids = deployed_devices[:5]
        pass_reasons = [
            f"{deployed_count} of {total_records} devices in the antivirus status report show a "
            f"non-NONE productName (e.g. device IDs {sample_ids}), confirming an EPP/antivirus agent "
            f"is installed and reporting on managed devices."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_records} devices in the antivirus status report have a productName "
            f"other than 'NONE'; no EPP/antivirus agent appears installed or reporting."
        ]
        recommendations = [
            "Deploy an antivirus/EPP agent (e.g. via NinjaOne policy) to managed endpoints so it "
            "reports through the antivirus-status query."
        ]

    result = {
        "isEPPDeployed": is_deployed,
        "devicesWithEPPProduct": deployed_count,
        "totalDevicesReported": total_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPDeployed",
            "vendor": "NinjaOne Endpoint management",
            "category": "epp",
        },
    )
