def transform(endpoints_response):
    """
    Evaluates safeguard types coverage based on endpoints response data
    and assigns a score from 0 to 100 for each safeguard type.

    Parameters:
        endpoints_response (dict): The JSON data containing endpoints information.

    Returns:
        dict: A dictionary summarizing the coverage score of each safeguard type.
    """

    # Initialize counters
    isEPPConfigured = endpoints_response.get("isEPPConfigured", True)
    if 'value' in endpoints_response:
        endpoints = endpoints_response['value']

    if not isEPPConfigured:
        isEPPConfigured = True if len(endpoints) > 0 else False

    total_endpoints = len(endpoints)
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

    for endpoint in endpoints_response.get("items", []):
        assigned_products = {product["code"]: product for product in endpoint.get("assignedProducts", [])}
        services = {service["name"]: service for service in endpoint.get("health", {}).get("services", {}).get("serviceDetails", [])}
        endpoint_type = endpoint.get("type")

        # Count total number of computers, servers, mobile devices, and cloud endpoints
        if endpoint_type == "computer":
            total_computers += 1
        elif endpoint_type == "server":
            total_servers += 1
        elif endpoint_type == "mobile":
            total_mobile_devices += 1

        if "cloud" in endpoint:
            total_cloud_endpoints += 1

        # 1. Endpoint Protection
        if endpoint_type == "computer" and "endpointProtection" in assigned_products:
            safeguard_counters["Endpoint Protection"] += 1

        # 1.1 Endpoint Security
        if endpoint_type == "computer" and "endpointProtection" in assigned_products:
            safeguard_counters["Endpoint Security"] += 1
            
        # 2. Server Protection
        if endpoint_type == "server" and "endpointProtection" in assigned_products:
            safeguard_counters["Server Protection"] += 1

        # 3. MDR (Managed Detection and Response)
        if "mtr" in assigned_products:
            safeguard_counters["MDR"] += 1

        # 4. Network Protection
        if any("Network Threat Protection" in service_name for service_name in services):
            safeguard_counters["Network Protection"] += 1

        # 5. Cloud Security
        if endpoint.get("cloud", {}).get("provider") and "endpointProtection" in assigned_products:
            safeguard_counters["Cloud Security"] += 1

        # 6. Mobile Protection
        if endpoint_type == "mobile" and "mobileProtection" in assigned_products:
            safeguard_counters["Mobile Protection"] += 1

        # 7. Email Security
        # Assuming email security products have specific codes; adjust as needed
        if "emailSecurity" in assigned_products:
            safeguard_counters["Email Security"] += 1

        # 8. Phishing Protection
        if "interceptX" in assigned_products:
            safeguard_counters["Phishing Protection"] += 1

        # 9. Zero Trust Network Access
        ztna_product = assigned_products.get("ztna")
        if ztna_product and ztna_product["status"] == "installed":
            safeguard_counters["Zero Trust Network Access"] += 1

        # 10. Encryption
        if endpoint.get("encryption", {}).get("volumes"):
            safeguard_counters["Encryption"] += 1

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
    
    #Endpoint Protection
    coverage_scores["isEPPEnabled"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEPPDeployed"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEPPLoggingEnabled"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEPPEnabledForCriticalSystems"] = coverage_scores["Endpoint Protection"] > 0
    coverage_scores["isEDRDeployed"] = coverage_scores["Endpoint Protection"] > 0

    #Endpoint Security
    coverage_scores["isEndpointSecurityEnabled"] = coverage_scores["Endpoint Security"] > 0
    
    #MDR
    coverage_scores["isMDREnabled"] = coverage_scores["MDR"] > 0    
    coverage_scores["isMDRLoggingEnabled"] = coverage_scores["MDR"] > 0
    coverage_scores["requiredCoveragePercentage"] = coverage_scores["Endpoint Protection"]
    coverage_scores["requiredConfigurationPercentage"] = coverage_scores["Endpoint Protection"]
    
    coverage_scores["isEPPConfigured"] = isEPPConfigured
    
    return coverage_scores
