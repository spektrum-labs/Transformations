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


CRITERIA_KEY = "isEDREnabled"
META = {"transformationId": "isEDREnabled", "vendor": "CrowdStrike Falcon", "category": "epp"}


def not_measured(validation, reason, api_errors, input_summary):
    """No verdict: the response is not a device list from the Hosts API."""
    return create_response(
        result={CRITERIA_KEY: None, "totalDevices": None, "enabledCount": None},
        validation=validation,
        fail_reasons=[reason],
        recommendations=["Verify the CrowdStrike API client (clientId/clientSecret) has Hosts: Read and re-run the evaluation."],
        input_summary=input_summary,
        api_errors=api_errors,
        metadata=META,
    )


def is_true(value):
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def transform(input):
    """
    isEDREnabled: at least one Falcon sensor is running with full EDR telemetry.

    Source: getAssetDetails (GET /devices/entities/devices/v2 via the Hosts API), the same
    device records isEDRDeployed reads. A sensor counts as enabled when it is not in Reduced
    Functionality Mode, reports an agent_version, and has a sensor_update policy assigned.

    Fail closed: anything that is not a Hosts API device page (error envelope, 401/403 body,
    empty or unrelated JSON) returns None, not False. An empty device page with a zero total
    from the API is a real measurement and returns False.
    """
    data, validation = extract_input(input)
    if not isinstance(data, dict):
        return not_measured(validation, "Input is not a CrowdStrike Hosts API response.", ["unexpected input type"], {})

    api_errors = []
    errors = data.get("errors")
    if isinstance(errors, list) and len(errors) > 0:
        first = errors[0] if isinstance(errors[0], dict) else {}
        api_errors.append("CrowdStrike API error: " + str(first.get("message") or first.get("code") or errors[0]))
    if data.get("error") is True or data.get("errorType") or data.get("status") == "Error":
        api_errors.append("getAssetDetails API error: " + str(data.get("errorMessage") or data.get("message") or "unknown"))
    if api_errors:
        return not_measured(validation, "The getAssetDetails call failed, so EDR state was not measured.", api_errors, {})

    resources = data.get("resources")
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    if not isinstance(resources, list):
        return not_measured(validation, "The response carries no device list (resources), so EDR state was not measured.",
                            ["no resources array in the getAssetDetails response"], {})
    if len(resources) == 0 and "total" not in pagination:
        return not_measured(validation, "An empty device list without a total from the API is not a measurement.",
                            ["empty resources without meta.pagination.total"], {})

    total_devices = 0
    enabled_count = 0
    rfm_count = 0
    sample_hosts = []
    for device in resources:
        if not isinstance(device, dict):
            continue
        total_devices = total_devices + 1
        rfm = is_true(device.get("reduced_functionality_mode"))
        policies = device.get("device_policies") if isinstance(device.get("device_policies"), dict) else {}
        has_update_policy = bool(policies.get("sensor_update"))
        if rfm:
            rfm_count = rfm_count + 1
        if (not rfm) and bool(device.get("agent_version")) and has_update_policy:
            enabled_count = enabled_count + 1
            if len(sample_hosts) < 5:
                sample_hosts.append(str(device.get("hostname") or device.get("device_id") or "unknown"))

    input_summary = {"totalDevices": total_devices, "enabledCount": enabled_count, "rfmCount": rfm_count,
                     "apiTotal": pagination.get("total")}
    enabled = enabled_count > 0

    if enabled:
        pass_reasons = [str(enabled_count) + " of " + str(total_devices) + " Falcon sensors run with full EDR telemetry "
                        "(not in Reduced Functionality Mode, agent_version reported, sensor_update policy assigned), e.g. "
                        + ", ".join(sample_hosts) + "."]
        fail_reasons = []
        recommendations = []
        if rfm_count > 0:
            recommendations.append(str(rfm_count) + " sensor(s) are in Reduced Functionality Mode; restore them to full EDR.")
    else:
        pass_reasons = []
        if total_devices == 0:
            fail_reasons = ["The Hosts API reports no devices, so no Falcon sensor is running EDR."]
        else:
            fail_reasons = ["None of the " + str(total_devices) + " devices has a Falcon sensor outside Reduced Functionality "
                            "Mode with an agent_version and a sensor_update policy, so EDR is not confirmed enabled."]
        recommendations = ["Deploy the Falcon sensor, assign a sensor update policy, and clear Reduced Functionality Mode."]

    return create_response(
        result={CRITERIA_KEY: enabled, "totalDevices": total_devices, "enabledCount": enabled_count,
                "reducedFunctionalityModeCount": rfm_count},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=META,
    )
