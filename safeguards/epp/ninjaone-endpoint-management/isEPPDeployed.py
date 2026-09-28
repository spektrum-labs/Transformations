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

    total_devices = len(records)
    deployed_count = 0
    not_deployed_count = 0
    sample_deployed = []
    sample_not_deployed = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        product_name = rec.get("productName") or "NONE"
        device_id = rec.get("deviceId")
        if product_name and product_name != "NONE":
            deployed_count = deployed_count + 1
            if len(sample_deployed) < 5:
                sample_deployed.append(f"device {device_id}: {product_name}")
        else:
            not_deployed_count = not_deployed_count + 1
            if len(sample_not_deployed) < 5:
                sample_not_deployed.append(f"device {device_id}")

    if total_devices == 0:
        is_deployed = False
        pass_reasons = []
        fail_reasons = ["No antivirus-status records were returned for any device; cannot confirm EPP deployment."]
        recommendations = ["Verify the antivirus-status query returns data and that devices are enrolled with an EPP product."]
    else:
        deployment_ratio = deployed_count / total_devices
        is_deployed = deployment_ratio > 0.5
        if is_deployed:
            pass_reasons = [
                f"{deployed_count} of {total_devices} devices report a non-NONE productName in antivirus-status "
                f"(e.g. {', '.join(sample_deployed) if sample_deployed else 'n/a'}), confirming an EPP product is installed and reporting."
            ]
            fail_reasons = []
            recommendations = []
            if not_deployed_count > 0:
                recommendations = [
                    f"Investigate {not_deployed_count} device(s) reporting productName=NONE "
                    f"(e.g. {', '.join(sample_not_deployed) if sample_not_deployed else 'n/a'}) to ensure EPP is installed fleet-wide."
                ]
        else:
            pass_reasons = []
            fail_reasons = [
                f"Only {deployed_count} of {total_devices} devices report a non-NONE productName in antivirus-status "
                f"(e.g. {', '.join(sample_not_deployed) if sample_not_deployed else 'n/a'} report NONE), so EPP is not confirmed deployed across the fleet."
            ]
            recommendations = [
                "Deploy an endpoint protection product to the devices reporting productName=NONE in the antivirus-status report."
            ]

    result = {
        "isEPPDeployed": is_deployed,
        "totalDevices": total_devices,
        "deployedDeviceCount": deployed_count,
        "notDeployedDeviceCount": not_deployed_count,
    }

    input_summary = {
        "totalDevices": total_devices,
        "deployedDeviceCount": deployed_count,
        "notDeployedDeviceCount": not_deployed_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isEPPDeployed", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )
