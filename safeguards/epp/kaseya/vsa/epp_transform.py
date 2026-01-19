import json
import ast


def transform(input):
    """
    Evaluates EPP/EDR deployment and configuration status from Kaseya VSA API responses.
    Handles multiple safeguard evaluations: isEDRDeployed, isEPPDeployed, isEPPConfigured.

    Parameters:
        input (dict): The JSON data from Kaseya endpoints (getDevices, getEndpointProtectionPolicies).

    Returns:
        dict: A dictionary containing EPP/EDR coverage percentages and configuration status.
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

    except json.JSONDecodeError:
        return {
            "isEDRDeployed": 0,
            "isEPPDeployed": 0,
            "isEPPConfigured": False,
            "error": "Invalid JSON"
        }
    except Exception as e:
        return {
            "isEDRDeployed": 0,
            "isEPPDeployed": 0,
            "isEPPConfigured": False,
            "error": str(e)
        }
