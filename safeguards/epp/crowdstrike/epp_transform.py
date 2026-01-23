"""
Transformation: epp_transform (CrowdStrike)
Vendor: CrowdStrike Falcon
Category: Endpoint Security

Evaluates safeguard types coverage based on CrowdStrike Falcon API endpoints response data
and assigns a score from 0 to 100 for each safeguard type.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "epp_transform",
                "vendor": "CrowdStrike Falcon",
                "category": "Endpoint Security"
            }
        }
    }


def transform(endpoints_response, debug=False):
    try:
        if isinstance(endpoints_response, str):
            endpoints_response = json.loads(endpoints_response)
        elif isinstance(endpoints_response, bytes):
            endpoints_response = json.loads(endpoints_response.decode("utf-8"))

        data, validation = extract_input(endpoints_response)

        if validation.get("status") == "failed":
            return create_response(
                result={"isEPPEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        isEPPConfigured = data.get("isEPPConfigured", True) if isinstance(data, dict) else True

        # Handle different possible response structures from CrowdStrike API
        devices = []
        if isinstance(data, dict):
            if "resources" in data:
                if len(data["resources"]) > 0 and isinstance(data["resources"][0], dict):
                    devices = data["resources"]
                else:
                    devices = data.get("devices", [])
            elif "items" in data:
                devices = data.get("items", [])
            else:
                devices = data.get("devices", [])
        elif isinstance(data, list):
            devices = data

        total_endpoints = len(devices)
        total_computers = 0
        total_servers = 0
        total_mobile_devices = 0
        total_cloud_endpoints = 0

        safeguard_counters = {
            "Endpoint Protection": 0,
            "Endpoint Security": 0,
            "Server Protection": 0,
            "MDR": 0,
            "Network Protection": 0,
            "Cloud Security": 0,
            "Mobile Protection": 0,
            "Email Security": 0,
            "Phishing Protection": 0,
            "Zero Trust Network Access": 0,
            "Encryption": 0
        }

        for idx, device in enumerate(devices):
            device_status_raw = device.get("status") or device.get("Status") or ""
            device_status = str(device_status_raw).lower() if device_status_raw else ""
            sensor_version = device.get("agent_version") or device.get("agentVersion") or device.get("sensor_version") or device.get("sensorVersion") or ""
            system_product_name_raw = device.get("system_product_name") or device.get("systemProductName") or ""
            system_product_name = str(system_product_name_raw).lower() if system_product_name_raw else ""
            os_version_raw = device.get("os_version") or device.get("osVersion") or ""
            os_version = str(os_version_raw).lower() if os_version_raw else ""
            product_type_desc_raw = device.get("product_type_desc") or device.get("productTypeDesc") or ""
            product_type_desc = str(product_type_desc_raw).lower() if product_type_desc_raw else ""

            is_server = "server" in system_product_name or "server" in os_version or product_type_desc == "server"
            is_mobile = "ios" in os_version or "android" in os_version or "mobile" in system_product_name.lower() or product_type_desc == "mobile"
            endpoint_type = "server" if is_server else ("mobile" if is_mobile else "computer")

            status_lower = str(device_status).lower() if device_status else ""
            has_valid_status = device_status and status_lower not in ["offline", ""] and status_lower in ["normal", "contained", "containment_pending"]

            device_policies = device.get("device_policies") or device.get("devicePolicies") or {}
            prevention_policies = device_policies.get("prevention") or {}
            prevention_applied = prevention_policies.get("applied", False)

            has_active_sensor = has_valid_status and ((sensor_version and len(str(sensor_version).strip()) > 0) or prevention_applied)

            policy_id = prevention_policies.get("policy_id") or prevention_policies.get("policyId")
            applied = prevention_policies.get("applied", False)
            has_prevention_policy = bool((bool(prevention_policies) and prevention_policies != {}) and (bool(policy_id) or applied or len(prevention_policies) > 0))

            has_network_protection = has_prevention_policy or device.get("prevention_policy_assigned", False) or (device.get("network_interfaces", []) != [] and has_active_sensor)

            cloud_instance_id = device.get("instance_id") or device.get("cloud_instance_id")
            cloud_provider = device.get("cloud_provider") or device.get("service_provider")
            is_cloud = bool(cloud_instance_id or cloud_provider)

            rtr_state_raw = device.get("rtr_state") or device.get("rtrState") or ""
            rtr_state = str(rtr_state_raw).lower() if rtr_state_raw else ""
            licenses = device.get("licenses") or device.get("Licenses") or []
            license_str = " ".join([str(l).lower() for l in licenses]) if licenses else ""

            has_mdr = rtr_state == "enabled" or "overwatch" in license_str or "insight" in license_str or (has_active_sensor and has_prevention_policy)

            if endpoint_type == "computer":
                total_computers += 1
            elif endpoint_type == "server":
                total_servers += 1
            elif endpoint_type == "mobile":
                total_mobile_devices += 1

            if is_cloud:
                total_cloud_endpoints += 1

            has_epp = bool(has_active_sensor and has_prevention_policy)

            if endpoint_type == "computer" and has_epp:
                safeguard_counters["Endpoint Protection"] += 1
                safeguard_counters["Endpoint Security"] += 1

            if endpoint_type == "server" and has_epp:
                safeguard_counters["Server Protection"] += 1

            if has_network_protection:
                safeguard_counters["Network Protection"] += 1

            if is_cloud and has_epp:
                safeguard_counters["Cloud Security"] += 1

            if endpoint_type == "mobile" and has_active_sensor:
                safeguard_counters["Mobile Protection"] += 1

            email_policies = device_policies.get("email", {})
            if email_policies and email_policies != {}:
                safeguard_counters["Email Security"] += 1

            url_policies = device_policies.get("url", {})
            has_url_policy = ((url_policies and url_policies != {} and (url_policies.get("policy_id") or url_policies.get("applied", False))) or device.get("threat_intel_enabled", False))
            if has_url_policy:
                safeguard_counters["Phishing Protection"] += 1

            zta_status = device.get("zero_trust_assessment", {})
            zta_enabled = ((zta_status and isinstance(zta_status, dict) and zta_status.get("enabled", False)) or device.get("zt_assessment_enabled", False))
            if zta_enabled:
                safeguard_counters["Zero Trust Network Access"] += 1

            disk_encryption = device.get("disk_encryption", {})
            if disk_encryption.get("status") == "encrypted" or device.get("encryption_status") == "encrypted":
                safeguard_counters["Encryption"] += 1

            if has_mdr:
                safeguard_counters["MDR"] += 1

        coverage_scores = {}
        coverage_scores["Endpoint Protection"] = round((safeguard_counters["Endpoint Protection"] / total_computers) * 100 if total_computers > 0 else 0)
        coverage_scores["Endpoint Security"] = round((safeguard_counters["Endpoint Security"] / total_computers) * 100 if total_computers > 0 else 0)
        coverage_scores["Server Protection"] = round((safeguard_counters["Server Protection"] / total_servers) * 100 if total_servers > 0 else 0)
        coverage_scores["MDR"] = round((safeguard_counters["MDR"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Network Protection"] = round((safeguard_counters["Network Protection"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Cloud Security"] = round((safeguard_counters["Cloud Security"] / total_cloud_endpoints) * 100 if total_cloud_endpoints > 0 else 0)
        coverage_scores["Mobile Protection"] = round((safeguard_counters["Mobile Protection"] / total_mobile_devices) * 100 if total_mobile_devices > 0 else 0)
        coverage_scores["Email Security"] = round((safeguard_counters["Email Security"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Phishing Protection"] = round((safeguard_counters["Phishing Protection"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Zero Trust Network Access"] = round((safeguard_counters["Zero Trust Network Access"] / total_endpoints) * 100 if total_endpoints > 0 else 0)
        coverage_scores["Encryption"] = round((safeguard_counters["Encryption"] / total_endpoints) * 100 if total_endpoints > 0 else 0)

        coverage_scores["isEPPEnabled"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPDeployed"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPLoggingEnabled"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEPPEnabledForCriticalSystems"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEDRDeployed"] = coverage_scores["Endpoint Protection"] > 0
        coverage_scores["isEndpointSecurityEnabled"] = coverage_scores["Endpoint Security"] > 0
        coverage_scores["isMDREnabled"] = coverage_scores["MDR"] > 0
        coverage_scores["isMDRLoggingEnabled"] = coverage_scores["MDR"] > 0
        coverage_scores["requiredCoveragePercentage"] = coverage_scores["MDR"]
        coverage_scores["requiredConfigurationPercentage"] = coverage_scores["MDR"]
        coverage_scores["isEPPConfigured"] = isEPPConfigured

        if coverage_scores["isEPPEnabled"]:
            pass_reasons.append(f"Endpoint protection enabled: {coverage_scores['Endpoint Protection']}% coverage")
        else:
            fail_reasons.append("Endpoint protection is not enabled")
            recommendations.append("Deploy CrowdStrike Falcon sensor to all computers")

        if coverage_scores["Server Protection"] > 0:
            pass_reasons.append(f"Server protection: {coverage_scores['Server Protection']}% coverage")

        if coverage_scores["isMDREnabled"]:
            pass_reasons.append(f"MDR enabled: {coverage_scores['MDR']}% coverage")

        return create_response(
            result=coverage_scores,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalEndpoints": total_endpoints,
                "totalComputers": total_computers,
                "totalServers": total_servers,
                "safeguardCounters": safeguard_counters
            }
        )

    except Exception as e:
        return create_response(
            result={"isEPPEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
