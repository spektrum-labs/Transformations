"""
Transformation: epp_transform (comprehensive)
Vendor: MDR / Endpoint Protection Platform
Category: Endpoint Security

Evaluates safeguard types coverage based on endpoints response data
and assigns a score from 0 to 100 for each safeguard type.
"""

import json
from datetime import datetime


def transform(input):
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
                        recommendations=None, input_summary=None, transformation_errors=None,
                        api_errors=None, additional_findings=None):
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
                    "transformationId": "epp_transform",
                    "vendor": "MDR Provider",
                    "category": "Endpoint Security"
                }
            }
        }

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isEPPEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Initialize counters
        isEPPConfigured = data.get("isEPPConfigured", True) if isinstance(data, dict) else True

        items = data.get("items", []) if isinstance(data, dict) else []
        total_endpoints = len(items)
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

        for endpoint in items:
            assigned_products = {product["code"]: product for product in endpoint.get("assignedProducts", [])}
            services = {service["name"]: service for service in endpoint.get("health", {}).get("services", {}).get("serviceDetails", [])}
            endpoint_type = endpoint.get("type")

            # Count total number of computers, servers, mobile devices, and cloud endpoints
            if endpoint_type == "computer":
                total_computers = total_computers + 1
            elif endpoint_type == "server":
                total_servers = total_servers + 1
            elif endpoint_type == "mobile":
                total_mobile_devices = total_mobile_devices + 1

            if "cloud" in endpoint:
                total_cloud_endpoints = total_cloud_endpoints + 1

            # 1. Endpoint Protection
            if endpoint_type == "computer" and "endpointProtection" in assigned_products:
                safeguard_counters["Endpoint Protection"] = safeguard_counters["Endpoint Protection"] + 1

            # 1.1 Endpoint Security
            if endpoint_type == "computer" and "endpointProtection" in assigned_products:
                safeguard_counters["Endpoint Security"] = safeguard_counters["Endpoint Security"] + 1

            # 2. Server Protection
            if endpoint_type == "server" and "endpointProtection" in assigned_products:
                safeguard_counters["Server Protection"] = safeguard_counters["Server Protection"] + 1

            # 3. MDR (Managed Detection and Response)
            if "mtr" in assigned_products or "xdr" in assigned_products:
                safeguard_counters["MDR"] = safeguard_counters["MDR"] + 1
            elif "mdrManaged" in endpoint:
                try:
                    if str(endpoint["mdrManaged"]).lower() != "false":
                        safeguard_counters["MDR"] = safeguard_counters["MDR"] + 1
                except:
                    pass

            # 4. Network Protection
            if any("Network Threat Protection" in service_name for service_name in services):
                safeguard_counters["Network Protection"] = safeguard_counters["Network Protection"] + 1

            # 5. Cloud Security
            if endpoint.get("cloud", {}).get("provider") and "endpointProtection" in assigned_products:
                safeguard_counters["Cloud Security"] = safeguard_counters["Cloud Security"] + 1

            # 6. Mobile Protection
            if endpoint_type == "mobile" and "mobileProtection" in assigned_products:
                safeguard_counters["Mobile Protection"] = safeguard_counters["Mobile Protection"] + 1

            # 7. Email Security
            if "emailSecurity" in assigned_products:
                safeguard_counters["Email Security"] = safeguard_counters["Email Security"] + 1

            # 8. Phishing Protection
            if "interceptX" in assigned_products:
                safeguard_counters["Phishing Protection"] = safeguard_counters["Phishing Protection"] + 1

            # 9. Zero Trust Network Access
            ztna_product = assigned_products.get("ztna")
            if ztna_product and ztna_product.get("status") == "installed":
                safeguard_counters["Zero Trust Network Access"] = safeguard_counters["Zero Trust Network Access"] + 1

            # 10. Encryption
            if endpoint.get("encryption", {}).get("volumes"):
                safeguard_counters["Encryption"] = safeguard_counters["Encryption"] + 1

        # Initialize coverage scores
        coverage_scores = {}

        # Calculate scores
        coverage_scores["Endpoint Protection"] = round(
            (safeguard_counters["Endpoint Protection"] / total_computers) * 100
            if total_computers > 0 else 0
        )

        coverage_scores["Endpoint Security"] = round(
            (safeguard_counters["Endpoint Security"] / total_computers) * 100
            if total_computers > 0 else 0
        )

        coverage_scores["Server Protection"] = round(
            (safeguard_counters["Server Protection"] / total_servers) * 100
            if total_servers > 0 else 0
        )

        coverage_scores["MDR"] = round(
            (safeguard_counters["MDR"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Network Protection"] = round(
            (safeguard_counters["Network Protection"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Cloud Security"] = round(
            (safeguard_counters["Cloud Security"] / total_cloud_endpoints) * 100
            if total_cloud_endpoints > 0 else 0
        )

        coverage_scores["Mobile Protection"] = round(
            (safeguard_counters["Mobile Protection"] / total_mobile_devices) * 100
            if total_mobile_devices > 0 else 0
        )

        coverage_scores["Email Security"] = round(
            (safeguard_counters["Email Security"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Phishing Protection"] = round(
            (safeguard_counters["Phishing Protection"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Zero Trust Network Access"] = round(
            (safeguard_counters["Zero Trust Network Access"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        coverage_scores["Encryption"] = round(
            (safeguard_counters["Encryption"] / total_endpoints) * 100
            if total_endpoints > 0 else 0
        )

        # Endpoint Protection boolean flags
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
        coverage_scores["requiredCoveragePercentage"] = coverage_scores["Endpoint Protection"]
        coverage_scores["requiredConfigurationPercentage"] = coverage_scores["Endpoint Protection"]

        coverage_scores["isEPPConfigured"] = isEPPConfigured

        # Build pass/fail reasons
        epp_coverage = coverage_scores.get('Endpoint Protection', 0)
        if coverage_scores["isEPPEnabled"]:
            if epp_coverage > 0:
                pass_reasons.append(f"Endpoint protection active: {epp_coverage}% of devices protected")
            else:
                pass_reasons.append("Endpoint protection configured but no devices currently protected")
                recommendations.append("Verify endpoint agent deployment status")
        else:
            fail_reasons.append("Endpoint protection not deployed or not reporting data")
            recommendations.append("Deploy endpoint protection to all computers")

        server_coverage = coverage_scores.get("Server Protection", 0)
        if server_coverage > 0:
            pass_reasons.append(f"Server protection active: {server_coverage}% of servers protected")

        mdr_coverage = coverage_scores.get("MDR", 0)
        if coverage_scores["isMDREnabled"]:
            if mdr_coverage > 0:
                pass_reasons.append(f"MDR active: {mdr_coverage}% coverage")
            else:
                pass_reasons.append("MDR configured but no devices currently monitored")

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
                "totalMobileDevices": total_mobile_devices,
                "totalCloudEndpoints": total_cloud_endpoints,
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
