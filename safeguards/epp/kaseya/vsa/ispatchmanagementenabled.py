"""
Transformation: isPatchManagementEnabled
Vendor: Kaseya
Category: Endpoint Protection

Evaluates isPatchManagementEnabled for Kaseya
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementEnabled", "vendor": "Kaseya", "category": "Endpoint Protection"}
        }
    }


def transform(input):
    criteriaKey = "isPatchManagementEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

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
                                    patch_date = datetime.strptime(last_patch_date[0:19], fmt)
                                    if patch_date >= sla_threshold:
                                        patched_devices = patched_devices + 1
                                    break
                                except ValueError:
                                    continue
                    except Exception:
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

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
