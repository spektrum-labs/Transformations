"""
Transformation: isEDRDeployed
Vendor: Kaseya
Category: Endpoint Protection

Evaluates isEDRDeployed for Kaseya
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEDRDeployed", "vendor": "Kaseya", "category": "Endpoint Protection"}
        }
    }


def transform(input):
    criteriaKey = "isEDRDeployed"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # Initialize result
        result = {
            "isEDRDeployed": 0,
            "isEPPDeployed": 0,
            "isEPPConfigured": False,
            "isEPPEnabled": False,
            "totalDevices": 0,
            "protectedDevices": 0,
            "edrProtectedDevices": 0
        }

        # Check if this is a policy response (for isEPPConfigured)
        if "policyId" in data or "Data" in data and isinstance(data.get("Data"), dict):
            policy_data = data.get("Data", data)

            # Check if policy is enabled and properly configured
            is_enabled = policy_data.get("enabled", False)
            policy_id = policy_data.get("id", policy_data.get("policyId", ""))
            policy_name = policy_data.get("name", policy_data.get("policyName", ""))
            settings = policy_data.get("settings", {})

            # EPP is configured if policy exists, is enabled, and has settings
            is_configured = bool(policy_id and is_enabled)

            # Check for specific security settings
            if settings:
                has_realtime = settings.get("realtimeProtection", settings.get("realTimeProtection", False))
                has_scanning = settings.get("scheduledScanning", settings.get("scheduledScans", False))
                has_behavioral = settings.get("behavioralAnalysis", settings.get("behaviorMonitoring", False))

                # Consider fully configured if key features are enabled
                is_configured = is_configured and (has_realtime or has_scanning or has_behavioral)

            result["isEPPConfigured"] = is_configured
            result["isEPPEnabled"] = is_enabled
            return result

        # Check if this is a devices response (for deployment coverage)
        devices = (
            data.get("devices", []) or
            data.get("Data", []) or
            data.get("items", []) or
            data.get("endpoints", []) or
            []
        )

        if isinstance(devices, list) and len(devices) > 0:
            total_devices = len(devices)
            epp_protected = 0
            edr_protected = 0

            for device in devices:
                if isinstance(device, list):
                    device = device[0] if len(device) > 0 else {}

                # Check device status
                device_status = str(device.get("status", "")).lower()
                is_online = device_status in ["online", "active", "connected"]

                # Check for EPP protection indicators
                has_epp = False
                antivirus_status = device.get("antivirus", device.get("antivirusStatus", {}))
                if isinstance(antivirus_status, dict):
                    has_epp = antivirus_status.get("enabled", False) or antivirus_status.get("installed", False)
                elif isinstance(antivirus_status, str):
                    has_epp = antivirus_status.lower() in ["enabled", "active", "protected", "installed"]

                # Check for endpoint protection policy assignment
                epp_policy = device.get("endpointProtectionPolicy", device.get("eppPolicy", ""))
                if epp_policy:
                    has_epp = True

                # Check for protection status fields
                protection_status = device.get("protectionStatus", device.get("securityStatus", "")).lower()
                if protection_status in ["protected", "secured", "enabled", "active"]:
                    has_epp = True

                # Check for EDR indicators
                has_edr = False
                edr_status = device.get("edrStatus", device.get("edr", {}))
                if isinstance(edr_status, dict):
                    has_edr = edr_status.get("enabled", False) or edr_status.get("deployed", False)
                elif isinstance(edr_status, str):
                    has_edr = edr_status.lower() in ["enabled", "active", "deployed"]

                # Check for XDR or advanced detection
                xdr_status = device.get("xdrStatus", device.get("advancedDetection", ""))
                if xdr_status:
                    has_edr = True

                # Check agent version presence (indicates deployment)
                agent_version = device.get("agentVersion", device.get("vsaAgentVersion", ""))
                if agent_version and not has_epp:
                    has_epp = True  # Agent installed indicates basic protection

                if has_epp:
                    epp_protected += 1
                if has_edr:
                    edr_protected += 1

            # Calculate coverage percentages
            result["totalDevices"] = total_devices
            result["protectedDevices"] = epp_protected
            result["edrProtectedDevices"] = edr_protected
            result["isEPPDeployed"] = round((epp_protected / total_devices) * 100) if total_devices > 0 else 0
            result["isEDRDeployed"] = round((edr_protected / total_devices) * 100) if total_devices > 0 else 0
            result["isEPPEnabled"] = epp_protected > 0

        return result

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
