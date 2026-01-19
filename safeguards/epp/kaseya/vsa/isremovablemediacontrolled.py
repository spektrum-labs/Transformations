import json
import ast


def transform(input):
    """
    Evaluates whether removable media controls are configured in Kaseya VSA.
    Checks endpoint protection policies for device control settings.

    Parameters:
        input (dict): The JSON data from Kaseya getEndpointProtectionPolicies endpoint.

    Returns:
        dict: A dictionary indicating if removable media is controlled.
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)

        # Navigate through response wrappers
        data = data.get("response", data)
        data = data.get("result", data)
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

    except json.JSONDecodeError:
        return {"isRemovableMediaControlled": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}
