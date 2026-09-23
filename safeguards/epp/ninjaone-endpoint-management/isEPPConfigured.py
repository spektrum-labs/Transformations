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
    deployed = []
    for r in records:
        if not isinstance(r, dict):
            continue
        product_name = r.get("productName") or "NONE"
        if product_name != "NONE":
            deployed.append(r)

    deployed_count = len(deployed)
    with_state = [r for r in deployed if r.get("productState")]
    on_count = sum(1 for r in with_state if r.get("productState") == "ON")
    off_count = sum(1 for r in with_state if r.get("productState") == "OFF")
    state_count = len(with_state)

    on_ratio = (on_count / state_count) if state_count > 0 else 0.0

    is_configured = state_count > 0 and on_ratio >= 0.5

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_configured:
        pass_reasons.append(
            "%d of %d devices with a reporting EPP product show productState=ON (%.1f%%), meeting the 50%% configured threshold." % (on_count, state_count, on_ratio * 100)
        )
    else:
        if state_count == 0:
            fail_reasons.append(
                "No devices among %d antivirus-status records report a productState value; EPP configuration cannot be confirmed." % total_records
            )
            recommendations.append(
                "Verify that the assigned policy pushes and enables an endpoint protection product so that productState reports ON."
            )
        else:
            fail_reasons.append(
                "Only %d of %d devices with a reporting EPP product show productState=ON (%.1f%%); %d devices report OFF, indicating EPP is installed but not actively configured/running under the assigned policy." % (on_count, state_count, on_ratio * 100, off_count)
            )
            recommendations.append(
                "Review the policy-assigned endpoint protection product configuration and enable real-time protection on devices currently reporting productState=OFF."
            )

    result = {
        "isEPPConfigured": is_configured,
        "totalDevicesReported": total_records,
        "devicesWithEPPProduct": deployed_count,
        "devicesWithProductState": state_count,
        "devicesConfiguredOn": on_count,
        "devicesConfiguredOff": off_count,
    }

    input_summary = {
        "totalRecords": total_records,
        "deployedCount": deployed_count,
        "stateReportingCount": state_count,
        "onCount": on_count,
        "offCount": off_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
