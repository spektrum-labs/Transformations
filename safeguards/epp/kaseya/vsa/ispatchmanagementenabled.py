import json
import ast
from datetime import datetime, timedelta


def transform(input):
    """
    Evaluates whether patch management is enabled and valid in Kaseya VSA.
    Checks patch management policies for enabled status and SLA compliance.

    Parameters:
        input (dict): The JSON data from Kaseya getPatchManagementPolicies or getDevices endpoints.

    Returns:
        dict: A dictionary indicating patch management status and validity.
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
            "isPatchManagementEnabled": False,
            "isPatchManagementValid": False,
            "policyEnabled": False,
            "scheduleConfigured": False,
            "totalDevices": 0,
            "patchedDevices": 0,
            "patchCoverage": 0
        }

        # Check if this is a policy response
        policy_data = data.get("Data", data)

        if "policyId" in policy_data or "id" in policy_data:
            # This is a single policy response
            is_enabled = policy_data.get("enabled", False)
            policy_id = policy_data.get("id", policy_data.get("policyId", ""))
            policy_name = policy_data.get("name", policy_data.get("policyName", ""))
            schedule = policy_data.get("schedule", {})

            result["policyEnabled"] = is_enabled
            result["isPatchManagementEnabled"] = bool(policy_id and is_enabled)

            # Check schedule configuration
            if schedule:
                has_schedule = (
                    schedule.get("enabled", False) or
                    schedule.get("frequency", "") or
                    schedule.get("startTime", "") or
                    schedule.get("recurrence", "")
                )
                result["scheduleConfigured"] = bool(has_schedule)
                result["isPatchManagementValid"] = result["isPatchManagementEnabled"] and has_schedule

            return result

        # Check if this is a devices response (for patch management validity/coverage)
        devices = (
            data.get("devices", []) or
            data.get("Data", []) or
            data.get("items", []) or
            []
        )

        if isinstance(devices, list) and len(devices) > 0:
            total_devices = len(devices)
            patched_devices = 0
            devices_with_policy = 0

            # SLA threshold - patches should be applied within 30 days
            sla_threshold = datetime.now() - timedelta(days=30)

            for device in devices:
                if isinstance(device, list):
                    device = device[0] if len(device) > 0 else {}

                # Check for patch management policy assignment
                patch_policy = device.get("patchManagementPolicy", device.get("patchPolicy", ""))
                if patch_policy:
                    devices_with_policy += 1

                # Check patch status
                patch_status = device.get("patchStatus", device.get("updateStatus", {}))
                if isinstance(patch_status, dict):
                    is_patched = patch_status.get("upToDate", False) or patch_status.get("compliant", False)
                    pending_patches = patch_status.get("pendingPatches", patch_status.get("pendingUpdates", 0))
                    critical_pending = patch_status.get("criticalPending", 0)

                    # Consider patched if up to date or no critical patches pending
                    if is_patched or (pending_patches == 0) or (critical_pending == 0):
                        patched_devices += 1
                elif isinstance(patch_status, str):
                    if patch_status.lower() in ["current", "compliant", "up-to-date", "uptodate"]:
                        patched_devices += 1

                # Check last patch date for SLA compliance
                last_patch_date = device.get("lastPatchDate", device.get("lastUpdateDate", ""))
                if last_patch_date:
                    try:
                        if isinstance(last_patch_date, str):
                            # Try common date formats
                            for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"]:
                                try:
                                    patch_date = datetime.strptime(last_patch_date[:19], fmt)
                                    if patch_date >= sla_threshold:
                                        patched_devices += 1
                                    break
                                except ValueError:
                                    continue
                    except:
                        pass

            # Calculate coverage
            result["totalDevices"] = total_devices
            result["patchedDevices"] = min(patched_devices, total_devices)  # Cap at total
            result["patchCoverage"] = round((result["patchedDevices"] / total_devices) * 100) if total_devices > 0 else 0

            # Patch management is enabled if any device has a policy
            result["isPatchManagementEnabled"] = devices_with_policy > 0

            # Patch management is valid if coverage meets threshold (e.g., 80%)
            coverage_threshold = 80
            result["isPatchManagementValid"] = result["patchCoverage"] >= coverage_threshold

        return result

    except json.JSONDecodeError:
        return {
            "isPatchManagementEnabled": False,
            "isPatchManagementValid": False,
            "error": "Invalid JSON"
        }
    except Exception as e:
        return {
            "isPatchManagementEnabled": False,
            "isPatchManagementValid": False,
            "error": str(e)
        }
