"""
Transformation: isassetdiscoveryenabled
Vendor: Axonius
Category: Asset Management

Checks if asset discovery adapters are configured and returning devices.
"""

import json
from datetime import datetime


def extract_input(input_data):
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
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isassetdiscoveryenabled",
                "vendor": "Axonius",
                "category": "Asset Management"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isAssetDiscoveryEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        discovery_enabled = False
        device_count = 0
        adapter_count = 0
        active_adapter_count = 0

        # Check for devices data (merged from getDevices)
        devices = data.get('devices', {})
        if isinstance(devices, dict):
            devices_data = devices.get('apiResponse', devices)
            assets = devices_data.get('assets', devices_data.get('data', []))
            if isinstance(assets, list):
                device_count = len(assets)
                if device_count > 0:
                    discovery_enabled = True
                    pass_reasons.append(f"{device_count} devices discovered")

        # Check for adapters data (merged from getAdapters)
        adapters = data.get('adapters', {})
        if isinstance(adapters, dict):
            adapters_data = adapters.get('apiResponse', adapters)
            adapter_list = adapters_data if isinstance(adapters_data, list) else adapters_data.get('data', [])
            if isinstance(adapter_list, list):
                active_adapters = [a for a in adapter_list if a.get('status', '') == 'success' or a.get('node_name')]
                adapter_count = len(adapter_list)
                active_adapter_count = len(active_adapters)
                if active_adapter_count > 0:
                    discovery_enabled = True
                    pass_reasons.append(f"{active_adapter_count} active adapters configured")
                else:
                    fail_reasons.append("No active adapters found")
                    recommendations.append("Configure and activate at least one discovery adapter")

        # Fallback: check for any data presence
        if not discovery_enabled and 'data' in data:
            fallback_data = data['data']
            if isinstance(fallback_data, list) and len(fallback_data) > 0:
                discovery_enabled = True
                device_count = len(fallback_data)
                pass_reasons.append(f"{device_count} items found in data")

        if not discovery_enabled:
            fail_reasons.append("No devices or active adapters found")
            recommendations.append("Enable asset discovery by configuring Axonius adapters")

        return create_response(
            result={
                "isAssetDiscoveryEnabled": discovery_enabled,
                "deviceCount": device_count,
                "adapterCount": adapter_count,
                "activeAdapters": active_adapter_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "hasDevicesData": bool(data.get('devices')),
                "hasAdaptersData": bool(data.get('adapters')),
                "deviceCount": device_count,
                "adapterCount": adapter_count,
                "activeAdapterCount": active_adapter_count
            }
        )

    except Exception as e:
        return create_response(
            result={"isAssetDiscoveryEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
