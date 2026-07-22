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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("errorType"):
        err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"getDeviceDetails API error: {err_msg}")

    resources = data.get("resources") or []
    if not isinstance(resources, list):
        resources = []

    total_devices = len(resources)
    deployed_count = 0
    rfm_count = 0
    stale_count = 0
    sample_hosts = []

    for device in resources:
        if not isinstance(device, dict):
            continue
        rfm = device.get("reduced_functionality_mode")
        rfm_is_true = rfm is True or (isinstance(rfm, str) and rfm.strip().lower() == "true")
        device_policies = device.get("device_policies") or {}
        has_sensor_update_policy = isinstance(device_policies, dict) and bool(device_policies.get("sensor_update"))
        agent_version = device.get("agent_version")
        last_seen = device.get("last_seen")

        if rfm_is_true:
            rfm_count = rfm_count + 1

        is_deployed_and_streaming = (not rfm_is_true) and bool(agent_version) and has_sensor_update_policy
        if is_deployed_and_streaming:
            deployed_count = deployed_count + 1
            if len(sample_hosts) < 5:
                sample_hosts.append(device.get("hostname") or device.get("device_id") or "unknown")
        elif not last_seen:
            stale_count = stale_count + 1

    is_edr_deployed = total_devices > 0 and deployed_count > 0

    input_summary = {
        "totalDevices": total_devices,
        "deployedCount": deployed_count,
        "rfmCount": rfm_count,
    }

    if api_errors:
        return create_response(
            result={"isEDRDeployed": False, "totalDevices": 0, "deployedCount": 0},
            validation=validation,
            fail_reasons=[f"Unable to evaluate EDR deployment because the getDeviceDetails API call failed: {api_errors[0]}"],
            recommendations=["Verify CrowdStrike API credentials (clientId/clientSecret) and OAuth scopes for the Hosts collection, then re-run the scan."],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={"transformationId": "isEDRDeployed", "vendor": "CrowdStrike Falcon", "category": "epp"},
        )

    if total_devices == 0:
        return create_response(
            result={"isEDRDeployed": False, "totalDevices": 0, "deployedCount": 0},
            validation=validation,
            fail_reasons=["No device records were returned by getDeviceDetails, so no Falcon sensor deployment could be confirmed."],
            recommendations=["Confirm devices are enrolled in the CrowdStrike Falcon tenant and that the API client has access to the Hosts collection."],
            input_summary=input_summary,
            metadata={"transformationId": "isEDRDeployed", "vendor": "CrowdStrike Falcon", "category": "epp"},
        )

    if is_edr_deployed:
        pass_reasons = [
            f"{deployed_count} of {total_devices} devices report reduced_functionality_mode=false, a populated agent_version, and an assigned sensor_update policy (e.g. {', '.join([str(h) for h in sample_hosts])}), confirming the Falcon sensor is installed and actively streaming EDR telemetry."
        ]
        fail_reasons = []
        recommendations = []
        if rfm_count > 0:
            recommendations.append(f"{rfm_count} device(s) are in Reduced Functionality Mode; investigate connectivity/licensing issues for those hosts to restore full EDR telemetry.")
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_devices} devices returned by getDeviceDetails have both reduced_functionality_mode=false and an assigned sensor_update policy with a populated agent_version, so EDR telemetry cannot be confirmed as active."
        ]
        recommendations = ["Investigate why Falcon sensors are reporting Reduced Functionality Mode or missing sensor_update policy assignment; reinstall or re-license affected sensors to restore full EDR streaming."]

    return create_response(
        result={
            "isEDRDeployed": is_edr_deployed,
            "totalDevices": total_devices,
            "deployedCount": deployed_count,
            "reducedFunctionalityModeCount": rfm_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isEDRDeployed", "vendor": "CrowdStrike Falcon", "category": "epp"},
    )
