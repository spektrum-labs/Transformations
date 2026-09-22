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

    devices = data.get("devices")
    if not isinstance(devices, list):
        devices = []

    reported_count_field = data.get("count")
    total_devices = reported_count_field if isinstance(reported_count_field, int) else len(devices)

    reporting_devices = []
    mdm_connector_devices = []
    pending_devices = []

    for d in devices:
        if not isinstance(d, dict):
            continue
        activation_status = d.get("activation_status")
        checkin_time = d.get("checkin_time")
        details = d.get("details")
        details = details if isinstance(details, dict) else {}
        has_mdm_indicator = bool(d.get("mdm_type")) or bool(details.get("mdm_connector_id")) or bool(details.get("mdm_connector_uuid"))

        if has_mdm_indicator:
            mdm_connector_devices.append(d)

        if activation_status == "ACTIVATED" and checkin_time:
            reporting_devices.append(d)
        elif activation_status == "PENDING":
            pending_devices.append(d)

    reporting_count = len(reporting_devices)
    mdm_connector_count = len(mdm_connector_devices)
    pending_count = len(pending_devices)
    sampled_count = len(devices)

    device_management_state = reporting_count > 0

    if device_management_state:
        sample = reporting_devices[0]
        sample_guid = sample.get("guid", "unknown")
        sample_checkin = sample.get("checkin_time", "unknown")
        pass_reasons = [
            f"{reporting_count} of {sampled_count} sampled devices report activation_status='ACTIVATED' with a non-null checkin_time "
            f"(e.g. device {sample_guid} last checked in at {sample_checkin}), indicating active MDM connector reporting.",
        ]
        if mdm_connector_count:
            pass_reasons.append(
                f"{mdm_connector_count} of {sampled_count} sampled devices additionally carry an mdm_type or details.mdm_connector_id/uuid, "
                f"confirming enrollment through an MDM/UEM connector."
            )
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {sampled_count} sampled devices report activation_status='ACTIVATED' with a non-null checkin_time; "
            f"{pending_count} devices remain in PENDING activation state and have not yet reported through an MDM connector."
        ]
        recommendations = [
            "Confirm devices complete MDM connector activation (e.g. Intune enrollment via mdm_connector_id) and verify they are "
            "checking in to Lookout; devices stuck in PENDING are not actively connected/reporting."
        ]

    result = {
        "deviceManagementState": device_management_state,
        "totalDevices": total_devices,
        "sampledDevices": sampled_count,
        "reportingDevices": reporting_count,
        "mdmConnectorDevices": mdm_connector_count,
        "pendingDevices": pending_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDevices": total_devices,
            "sampledDevices": sampled_count,
            "reportingDevices": reporting_count,
            "mdmConnectorDevices": mdm_connector_count,
            "pendingDevices": pending_count,
        },
        metadata={
            "transformationId": "deviceManagementState",
            "vendor": "Lookout",
            "category": "mobile-security",
        },
    )
