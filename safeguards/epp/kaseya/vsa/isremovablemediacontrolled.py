"""
Transformation: isRemovableMediaControlled
Vendor: Kaseya
Category: Endpoint Protection

Evaluates isRemovableMediaControlled for Kaseya
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRemovableMediaControlled", "vendor": "Kaseya", "category": "Endpoint Protection"}
        }
    }


def transform(input):
    criteriaKey = "isRemovableMediaControlled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # Initialize result
        result = {
            "isRemovableMediaControlled": False,
            "deviceControlEnabled": False,
            "usbBlocked": False,
            "removableStorageRestricted": False
        }

        # Get policy data
        policy_data = data.get("Data", data)

        # Check if policy is enabled first
        is_enabled = policy_data.get("enabled", False)
        if not is_enabled:
            return result

        # Get settings from policy
        settings = policy_data.get("settings", {})
        if not settings:
            return result

        # Check for device control settings
        device_control = settings.get("deviceControl", settings.get("DeviceControl", {}))
        if isinstance(device_control, dict):
            # Check if device control is enabled
            dc_enabled = device_control.get("enabled", device_control.get("Enabled", False))
            result["deviceControlEnabled"] = dc_enabled

            # Check for USB restrictions
            usb_settings = device_control.get("usb", device_control.get("USB", {}))
            if isinstance(usb_settings, dict):
                usb_blocked = (
                    usb_settings.get("blocked", False) or
                    usb_settings.get("restricted", False) or
                    usb_settings.get("mode", "").lower() in ["block", "deny", "restricted"]
                )
                result["usbBlocked"] = usb_blocked
            elif isinstance(usb_settings, str):
                result["usbBlocked"] = usb_settings.lower() in ["blocked", "restricted", "deny"]

            # Check for removable storage restrictions
            removable_storage = device_control.get("removableStorage", device_control.get("RemovableStorage", {}))
            if isinstance(removable_storage, dict):
                storage_restricted = (
                    removable_storage.get("blocked", False) or
                    removable_storage.get("restricted", False) or
                    removable_storage.get("readOnly", False) or
                    removable_storage.get("mode", "").lower() in ["block", "deny", "readonly", "restricted"]
                )
                result["removableStorageRestricted"] = storage_restricted
            elif isinstance(removable_storage, str):
                result["removableStorageRestricted"] = removable_storage.lower() in ["blocked", "restricted", "readonly"]

        # Check for alternative device control paths
        if not result["deviceControlEnabled"]:
            # Check direct settings paths
            usb_control = settings.get("usbControl", settings.get("USBControl", settings.get("usbPolicy", {})))
            if usb_control:
                if isinstance(usb_control, dict):
                    result["deviceControlEnabled"] = usb_control.get("enabled", False)
                    result["usbBlocked"] = usb_control.get("blockAll", usb_control.get("restricted", False))
                elif isinstance(usb_control, bool):
                    result["deviceControlEnabled"] = usb_control
                    result["usbBlocked"] = usb_control

            # Check for removable media policy
            media_policy = settings.get("removableMediaPolicy", settings.get("mediaControl", {}))
            if media_policy:
                if isinstance(media_policy, dict):
                    result["removableStorageRestricted"] = (
                        media_policy.get("enabled", False) or
                        media_policy.get("restricted", False)
                    )
                elif isinstance(media_policy, bool):
                    result["removableStorageRestricted"] = media_policy

        # Determine overall control status
        result["isRemovableMediaControlled"] = (
            result["deviceControlEnabled"] or
            result["usbBlocked"] or
            result["removableStorageRestricted"]
        )

        return result

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
