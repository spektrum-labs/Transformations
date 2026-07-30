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
    if data.get("error") is True or data.get("statusCode") == 500:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    resources = data.get("resources") or data.get("data") or []
    if not isinstance(resources, list):
        resources = []

    total_policies = len(resources)
    enabled_controlling_policies = []
    controlled_classes = ["BLOCK_ALL", "BLOCK", "READ_ONLY", "FULL_ACCESS_MASS_STORAGE_ONLY"]

    for policy in resources:
        if not isinstance(policy, dict):
            continue
        if not policy.get("enabled"):
            continue
        settings = policy.get("settings") or {}
        if not isinstance(settings, dict):
            settings = {}
        usb_settings = settings.get("usb_device_control_settings") or {}
        if not isinstance(usb_settings, dict):
            usb_settings = {}
        classes = usb_settings.get("classes") or []
        if not isinstance(classes, list):
            classes = []

        controls_usb = False
        for cls in classes:
            if not isinstance(cls, dict):
                continue
            action = cls.get("action") or ""
            if action and action != "FULL_ACCESS":
                controls_usb = True
                break

        groups = policy.get("groups") or []
        if controls_usb and (isinstance(groups, list) and len(groups) > 0):
            enabled_controlling_policies.append(policy.get("name") or policy.get("id") or "unknown")

    is_controlled = len(enabled_controlling_policies) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_controlled:
        pass_reasons.append(
            f"Found {len(enabled_controlling_policies)} enabled device-control "
            f"policy(ies) with restrictive USB class actions assigned to host groups: "
            f"{', '.join(enabled_controlling_policies)} (out of {total_policies} total policies)."
        )
    else:
        if total_policies == 0:
            fail_reasons.append(
                "No device-control policies were returned by getCombinedDeviceControlPolicies "
                "(0 resources), so removable-media restrictions cannot be confirmed."
            )
        else:
            fail_reasons.append(
                f"None of the {total_policies} device-control policy(ies) returned are both "
                f"enabled=true and assigned to a host group with a restrictive "
                f"usb_device_control_settings.classes[].action (e.g. BLOCK_ALL); mass-storage "
                f"devices are not being controlled."
            )
        recommendations.append(
            "Create and enable a Device Control policy in Falcon with USB mass-storage class "
            "actions set to BLOCK_ALL or READ_ONLY, and assign it to the relevant host groups."
        )

    result = {
        "isRemovableMediaControlled": is_controlled,
        "totalDeviceControlPolicies": total_policies,
        "enabledControllingPolicies": len(enabled_controlling_policies),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPolicies": total_policies,
            "enabledControllingPolicies": len(enabled_controlling_policies),
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isRemovableMediaControlled",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
