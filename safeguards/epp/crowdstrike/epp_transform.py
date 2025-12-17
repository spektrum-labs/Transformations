def transform(endpoints_response, debug=False):
    """
    Evaluates safeguard types coverage based on CrowdStrike Falcon API endpoints response data
    and assigns a score from 0 to 100 for each safeguard type.
    
    This transform maps CrowdStrike Falcon API responses to the same criteria structure
    used by Sophos EPP transformations.

    Parameters:
        endpoints_response (dict): The JSON data containing CrowdStrike device/host information.
                                  Expected structure from CrowdStrike APIs:
                                  - GET /devices/queries/devices/v1 (query device IDs)
                                  - GET /devices/entities/devices/v2 (get device details)
                                  - Response includes: resources (list of devices), each with:
                                    device_id, hostname, status, os_version, sensor_version,
                                    device_policies, system_product_name, etc.
        debug (bool): If True, prints detailed field detection information for each device.

    Returns:
        dict: A dictionary summarizing the coverage score of each safeguard type.
    """

    # Initialize counters
    isEPPConfigured = endpoints_response.get("isEPPConfigured", True)
    
    # Import json for debug output (if debug mode is enabled)
    import json
    
    # Handle different possible response structures from CrowdStrike API
    # CrowdStrike API may return: {"resources": [...]} or {"items": [...]} or direct list
    devices = []
    if "resources" in endpoints_response:
        # Standard CrowdStrike API response format
        device_ids = endpoints_response.get("resources", [])
        # If we have device details in the response, use them
        if "resources" in endpoints_response and isinstance(endpoints_response["resources"], list):
            if len(endpoints_response["resources"]) > 0 and isinstance(endpoints_response["resources"][0], dict):
                devices = endpoints_response["resources"]
            else:
                # We have device IDs but need to fetch details - assume details are provided
                devices = endpoints_response.get("devices", [])
    elif "items" in endpoints_response:
        # Alternative format (matching Sophos structure)
        devices = endpoints_response.get("items", [])
    elif isinstance(endpoints_response, list):
        devices = endpoints_response
    else:
        devices = endpoints_response.get("devices", [])
    
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
        # CrowdStrike device structure mapping
        # Map CrowdStrike fields to our standard structure
        # Handle both snake_case and camelCase field names
        device_id = device.get("device_id") or device.get("deviceId", f"device_{idx}")
        hostname = device.get("hostname") or device.get("hostName", "unknown")
        
        # Status: handle both naming conventions and case variations
        device_status_raw = device.get("status") or device.get("Status") or ""
        device_status = str(device_status_raw).lower() if device_status_raw else ""
        
        # Sensor/Agent version: handle both naming conventions
        # CrowdStrike API uses 'agent_version' not 'sensor_version'
        sensor_version = device.get("agent_version") or device.get("agentVersion") or device.get("sensor_version") or device.get("sensorVersion") or ""
        
        # System/product info: handle both naming conventions
        system_product_name_raw = device.get("system_product_name") or device.get("systemProductName") or ""
        system_product_name = str(system_product_name_raw).lower() if system_product_name_raw else ""
        
        os_version_raw = device.get("os_version") or device.get("osVersion") or ""
        os_version = str(os_version_raw).lower() if os_version_raw else ""
        
        if debug:
            print(f"\n{'='*80}")
            print(f"DEBUG: Device {idx + 1}/{len(devices)} - {hostname} ({device_id})")
            print(f"{'='*80}")
            print(f"  Raw Fields from API:")
            print(f"    status: {device.get('status')} (type: {type(device.get('status')).__name__})")
            print(f"    agent_version: {device.get('agent_version')} (type: {type(device.get('agent_version')).__name__})")
            print(f"    sensor_version: {device.get('sensor_version')} (type: {type(device.get('sensor_version')).__name__})")
            print(f"    system_product_name: {device.get('system_product_name')}")
            print(f"    os_version: {device.get('os_version')}")
            print(f"    product_type_desc: {device.get('product_type_desc')}")
            print(f"    rtr_state: {device.get('rtr_state')}")
            print(f"    licenses: {device.get('licenses')}")
            print(f"    prevention_policy_assigned: {device.get('prevention_policy_assigned')}")
            print(f"    device_policies keys: {list(device.get('device_policies', {}).keys())}")
            print(f"    device_policies: {json.dumps(device.get('device_policies', {}), indent=6)}")
            print(f"  All device keys: {list(device.keys())[:20]}")  # Show first 20 keys
        
        # Determine device type based on OS and product name
        # CrowdStrike doesn't explicitly separate computer/server, so we infer from OS
        # Handle both snake_case and camelCase field names
        product_type_desc_raw = device.get("product_type_desc") or device.get("productTypeDesc") or ""
        product_type_desc = str(product_type_desc_raw).lower() if product_type_desc_raw else ""
        machine_domain_raw = device.get("machine_domain") or device.get("machineDomain") or ""
        machine_domain = str(machine_domain_raw).lower() if machine_domain_raw else ""
        
        is_server = (
            "server" in system_product_name or 
            "server" in os_version or
            product_type_desc == "server" or
            machine_domain == "server"
        )
        is_mobile = (
            "ios" in os_version or 
            "android" in os_version or
            "mobile" in system_product_name.lower() or
            product_type_desc == "mobile"
        )
        
        endpoint_type = "server" if is_server else ("mobile" if is_mobile else "computer")
        
        if debug:
            print(f"  Device Type Detection:")
            print(f"    product_type_desc (snake_case): {device.get('product_type_desc')}")
            print(f"    productTypeDesc (camelCase): {device.get('productTypeDesc')}")
            print(f"    product_type_desc found: {product_type_desc}")
            print(f"    system_product_name: {device.get('system_product_name') or device.get('systemProductName')}")
            print(f"    os_version: {device.get('os_version') or device.get('osVersion')}")
            print(f"    is_server: {is_server}")
            print(f"    is_mobile: {is_mobile}")
            print(f"    endpoint_type: {endpoint_type}")
        
        # Check if device has active sensor (equivalent to endpointProtection)
        # Sensor is active if:
        # 1. Status is normal/contained (not offline)
        # 2. Either agent_version exists OR prevention policy is applied (indicates active sensor)
        # CrowdStrike API uses 'agent_version' field, not 'sensor_version'
        status_lower = str(device_status).lower() if device_status else ""
        has_valid_status = (
            device_status and
            status_lower not in ["offline", ""] and
            status_lower in ["normal", "contained", "containment_pending"]
        )
        
        # Get prevention policy to check if applied (indicates sensor is active)
        device_policies = device.get("device_policies") or device.get("devicePolicies") or {}
        prevention_policies = device_policies.get("prevention") or {}
        prevention_applied = prevention_policies.get("applied", False)
        
        # Sensor is active if status is valid AND (agent_version exists OR prevention policy is applied)
        has_active_sensor = (
            has_valid_status and
            (
                (sensor_version and len(str(sensor_version).strip()) > 0) or
                prevention_applied  # If prevention policy is applied, sensor must be active
            )
        )
        
        if debug:
            print(f"  Detection Results:")
            print(f"    Raw status: {device.get('status')}")
            print(f"    Normalized status: {status_lower}")
            print(f"    agent_version: {device.get('agent_version')}")
            print(f"    sensor_version (fallback): {device.get('sensor_version')}")
            print(f"    sensor_version found: {sensor_version}")
            print(f"    prevention_policies.applied: {prevention_applied}")
            print(f"    has_active_sensor: {has_active_sensor}")
            print(f"      - status check: {has_valid_status}")
            print(f"      - agent_version check: {bool(sensor_version and len(str(sensor_version).strip()) > 0)}")
            print(f"      - prevention_applied check: {prevention_applied}")
        
        # Get device policies (prevention policies, sensor update policies, etc.)
        # Handle both snake_case and camelCase field names
        # Note: device_policies already retrieved above for has_active_sensor check
        if 'device_policies' not in locals():
            device_policies = device.get("device_policies") or device.get("devicePolicies") or {}
        prevention_policies = device_policies.get("prevention") or {}
        sensor_update_policies = device_policies.get("sensor_update") or device_policies.get("sensorUpdate") or {}
        
        # Check for prevention policy (equivalent to endpoint protection features)
        # Prevention policy can be indicated by:
        # 1. device_policies.prevention exists and has policy_id (handle both naming conventions)
        # 2. device_policies.prevention.applied is True (primary indicator - policy is applied)
        # 3. device_policies.prevention exists (non-empty dict) - indicates policy is configured
        # Note: 'prevention_policy_assigned' field doesn't exist in actual API response
        policy_id = prevention_policies.get("policy_id") or prevention_policies.get("policyId")
        applied = prevention_policies.get("applied", False)
        
        # Check if prevention policy exists and is configured/applied
        has_prevention_policy = bool(
            (bool(prevention_policies) and prevention_policies != {}) and 
            (bool(policy_id) or applied or len(prevention_policies) > 0)
        )
        
        if debug:
            print(f"    Prevention Policy Detection:")
            print(f"      - Checking device_policies (snake_case): {device.get('device_policies')}")
            print(f"      - Checking devicePolicies (camelCase): {device.get('devicePolicies')}")
            print(f"      - device_policies found: {bool(device_policies)}")
            print(f"      - prevention_policies: {prevention_policies}")
            print(f"      - prevention_policies.policy_id (snake_case): {prevention_policies.get('policy_id')}")
            print(f"      - prevention_policies.policyId (camelCase): {prevention_policies.get('policyId')}")
            print(f"      - policy_id found: {policy_id}")
            print(f"      - prevention_policies.applied: {applied}")
            print(f"      - has_prevention_policy: {has_prevention_policy} (boolean)")
        
        # Check for network protection features
        # CrowdStrike's prevention policies include network-based controls
        # Network protection is indicated by prevention policy or active network interfaces with sensor
        has_network_protection = (
            has_prevention_policy or
            device.get("prevention_policy_assigned", False) or
            (device.get("network_interfaces", []) != [] and has_active_sensor)
        )
        
        # Check for cloud instances
        cloud_instance_id = device.get("instance_id") or device.get("cloud_instance_id")
        cloud_provider = device.get("cloud_provider") or device.get("service_provider")
        is_cloud = bool(cloud_instance_id or cloud_provider)
        
        # Get RTR state for MDR detection
        # Handle both snake_case and camelCase field names
        # Note: 'licenses' field doesn't exist in actual API response
        rtr_state_raw = device.get("rtr_state") or device.get("rtrState") or ""
        rtr_state = str(rtr_state_raw).lower() if rtr_state_raw else ""
        
        # Try to get licenses if available (may not exist in API response)
        licenses = device.get("licenses") or device.get("Licenses") or []
        license_str = " ".join([str(l).lower() for l in licenses]) if licenses else ""
        
        # Check for MDR/XDR capabilities (CrowdStrike Falcon Insight, Falcon OverWatch)
        # MDR capabilities are indicated by:
        # 1. rtr_state enabled - Real-Time Response (RTR) enables remote investigation/response (MDR feature)
        # 2. Licenses containing "Falcon Insight" or "Falcon OverWatch" (MDR/XDR licenses)
        # 3. Active sensor with prevention policy (basic EDR/MDR capability)
        has_mdr = (
            rtr_state == "enabled" or  # Real-Time Response enabled indicates MDR capability
            "overwatch" in license_str or  # Falcon OverWatch is MDR service
            "insight" in license_str or  # Falcon Insight is EDR/XDR capability
            (has_active_sensor and has_prevention_policy)  # Active protection indicates basic MDR
        )
        
        if debug:
            print(f"    rtr_state: {device.get('rtr_state')} -> {rtr_state}")
            print(f"    licenses: {licenses}")
            print(f"    license_str: {license_str}")
            print(f"    has_mdr: {has_mdr}")
        
        # Count total number of computers, servers, mobile devices, and cloud endpoints
        if endpoint_type == "computer":
            total_computers += 1
        elif endpoint_type == "server":
            total_servers += 1
        elif endpoint_type == "mobile":
            total_mobile_devices += 1

        if is_cloud:
            total_cloud_endpoints += 1

        # 1. Endpoint Protection (EPP)
        # CrowdStrike: Active sensor with prevention policy = endpoint protection
        # EPP is enabled if: sensor is active AND prevention policy is applied
        has_epp = bool(
            has_active_sensor and has_prevention_policy
        )
        
        if debug:
            print(f"    EPP Detection Summary:")
            print(f"      has_active_sensor: {has_active_sensor}")
            print(f"      has_prevention_policy: {has_prevention_policy}")
            print(f"      has_epp: {has_epp} (boolean)")
            print(f"      endpoint_type: {endpoint_type}")
            print(f"    Safeguard Counters:")
        
        # Endpoint Protection: computers with EPP
        if endpoint_type == "computer" and has_epp:
            safeguard_counters["Endpoint Protection"] += 1
            if debug:
                print(f"      ✓ Endpoint Protection: +1 (computer with EPP)")
        
        # Endpoint Security: same as Endpoint Protection (computers with EPP)
        if endpoint_type == "computer" and has_epp:
            safeguard_counters["Endpoint Security"] += 1
            if debug:
                print(f"      ✓ Endpoint Security: +1 (computer with EPP)")
            
        # Server Protection: servers with EPP
        if endpoint_type == "server" and has_epp:
            safeguard_counters["Server Protection"] += 1
            if debug:
                print(f"      ✓ Server Protection: +1 (server with EPP)")

        # 3. Network Protection
        # CrowdStrike: Network-based prevention and detection capabilities
        if has_network_protection:
            safeguard_counters["Network Protection"] += 1

        # 5. Cloud Security
        # CrowdStrike: Cloud workload protection (cloud instance with active protection)
        if is_cloud and has_epp:
            safeguard_counters["Cloud Security"] += 1

        # 6. Mobile Protection
        # CrowdStrike: Mobile device support (Falcon for Mobile)
        if endpoint_type == "mobile" and has_active_sensor:
            safeguard_counters["Mobile Protection"] += 1

        # 7. Email Security
        # CrowdStrike doesn't have native email security, but can integrate
        # Check for email-related policies or integrations
        # Only count if email policy exists and is not empty
        email_policies = device_policies.get("email", {})
        if email_policies and email_policies != {}:
            safeguard_counters["Email Security"] += 1

        # 8. Phishing Protection
        # CrowdStrike: URL filtering and threat intelligence for phishing
        # Check for URL filtering policies or threat intelligence features
        # URL policy exists if it has policy_id or applied flag, or if threat_intel_enabled is True
        url_policies = device_policies.get("url", {})
        has_url_policy = (
            (url_policies and url_policies != {} and 
             (url_policies.get("policy_id") or url_policies.get("applied", False))) or
            device.get("threat_intel_enabled", False)
        )
        if has_url_policy:
            safeguard_counters["Phishing Protection"] += 1

        # 9. Zero Trust Network Access
        # CrowdStrike: Falcon Zero Trust Assessment or similar features
        # Check if zero trust assessment is enabled (not just present)
        zta_status = device.get("zero_trust_assessment", {})
        zta_enabled = (
            (zta_status and isinstance(zta_status, dict) and zta_status.get("enabled", False)) or
            device.get("zt_assessment_enabled", False)
        )
        if zta_enabled:
            safeguard_counters["Zero Trust Network Access"] += 1

        # 10. Encryption
        # CrowdStrike: Check for disk encryption status
        disk_encryption = device.get("disk_encryption", {})
        if disk_encryption.get("status") == "encrypted" or device.get("encryption_status") == "encrypted":
            safeguard_counters["Encryption"] += 1

        # 3. MDR (Managed Detection and Response)
        # CrowdStrike: rtr_state enabled, Falcon Insight/OverWatch licenses, or active sensor with prevention
        if has_mdr:
            safeguard_counters["MDR"] += 1
            if debug:
                print(f"      ✓ MDR: +1")

    # Initialize coverage scores
    coverage_scores = {}

    # Calculate scores
    coverage_scores["Endpoint Protection"] = (
        (safeguard_counters["Endpoint Protection"] / total_computers) * 100
        if total_computers > 0 else 0
    )

    coverage_scores["Endpoint Security"] = (
        (safeguard_counters["Endpoint Security"] / total_computers) * 100
        if total_computers > 0 else 0
    )

    coverage_scores["Server Protection"] = (
        (safeguard_counters["Server Protection"] / total_servers) * 100
        if total_servers > 0 else 0
    )

    coverage_scores["MDR"] = (
        (safeguard_counters["MDR"] / total_endpoints) * 100
        if total_endpoints > 0 else 0
    )

    coverage_scores["Network Protection"] = (
        (safeguard_counters["Network Protection"] / total_endpoints) * 100
        if total_endpoints > 0 else 0
    )

    coverage_scores["Cloud Security"] = (
        (safeguard_counters["Cloud Security"] / total_cloud_endpoints) * 100
        if total_cloud_endpoints > 0 else 0
    )

    coverage_scores["Mobile Protection"] = (
        (safeguard_counters["Mobile Protection"] / total_mobile_devices) * 100
        if total_mobile_devices > 0 else 0
    )

    coverage_scores["Email Security"] = (
        (safeguard_counters["Email Security"] / total_endpoints) * 100
        if total_endpoints > 0 else 0
    )

    coverage_scores["Phishing Protection"] = (
        (safeguard_counters["Phishing Protection"] / total_endpoints) * 100
        if total_endpoints > 0 else 0
    )

    coverage_scores["Zero Trust Network Access"] = (
        (safeguard_counters["Zero Trust Network Access"] / total_endpoints) * 100
        if total_endpoints > 0 else 0
    )

    coverage_scores["Encryption"] = (
        (safeguard_counters["Encryption"] / total_endpoints) * 100
        if total_endpoints > 0 else 0
    )

    # Round scores to nearest integer
    for key in coverage_scores:
        coverage_scores[key] = round(coverage_scores[key])
    
    # Endpoint Protection
    coverage_scores["isEPPEnabled"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEPPDeployed"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEPPLoggingEnabled"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEPPEnabledForCriticalSystems"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEDRDeployed"] = coverage_scores["Endpoint Protection"] > 0

    # Endpoint Security
    coverage_scores["isEndpointSecurityEnabled"] = coverage_scores["Endpoint Security"] > 0
    
    # MDR
    coverage_scores["isMDREnabled"] = coverage_scores["MDR"] > 0    
    coverage_scores["isMDRLoggingEnabled"] = coverage_scores["MDR"] > 0
    coverage_scores["requiredCoveragePercentage"] = coverage_scores["MDR"]
    coverage_scores["requiredConfigurationPercentage"] = coverage_scores["MDR"]
    
    coverage_scores["isEPPConfigured"] = isEPPConfigured
    
    return coverage_scores

