"""
Transformation: isEndpointCoverageValid
Vendor: Red Canary
Category: Cloud Security / Endpoint Coverage

Validates that endpoint coverage meets the required threshold.
Checks the endpoints endpoint for monitored endpoints and their status.
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
                "transformationId": "isEndpointCoverageValid",
                "vendor": "Red Canary",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isEndpointCoverageValid"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        coverage_valid = False
        total_endpoints = 0
        monitored_endpoints = 0
        unmonitored_endpoints = 0

        endpoints = []

        if isinstance(data, dict):
            if 'endpoints' in data and isinstance(data['endpoints'], list):
                endpoints = data['endpoints']
            elif 'data' in data and isinstance(data['data'], list):
                endpoints = data['data']

            # Check meta for total count
            meta = data.get('meta', {})
            if isinstance(meta, dict):
                total_from_meta = meta.get('total_count', meta.get('total', 0))
                if isinstance(total_from_meta, (int, float)) and total_from_meta > 0:
                    total_endpoints = int(total_from_meta)
        elif isinstance(data, list):
            endpoints = data

        if endpoints:
            total_endpoints = max(total_endpoints, len(endpoints))

            for endpoint in endpoints:
                if isinstance(endpoint, dict):
                    # Check monitoring status
                    is_monitored = endpoint.get('is_monitored', endpoint.get('monitored',
                                   endpoint.get('sensor_installed', None)))
                    status = str(endpoint.get('status', endpoint.get('state', ''))).lower()

                    if is_monitored is True or status in ('active', 'monitored', 'online', 'healthy'):
                        monitored_endpoints += 1
                    elif is_monitored is False or status in ('inactive', 'unmonitored', 'offline', 'unhealthy'):
                        unmonitored_endpoints += 1
                    else:
                        # No explicit status - assume monitored if endpoint exists in Red Canary
                        monitored_endpoints += 1

        if total_endpoints > 0:
            coverage_percentage = round((monitored_endpoints / total_endpoints) * 100, 1)

            # Coverage is valid if endpoints are being monitored
            if monitored_endpoints > 0:
                coverage_valid = True
                pass_reasons.append(
                    f"Endpoint coverage is valid ({monitored_endpoints} of {total_endpoints} "
                    f"endpoints monitored, {coverage_percentage}% coverage)"
                )
            else:
                fail_reasons.append(
                    f"No monitored endpoints found out of {total_endpoints} total endpoints"
                )
                recommendations.append("Ensure Red Canary sensors are deployed and active on endpoints")

            if unmonitored_endpoints > 0:
                additional_findings.append(
                    f"{unmonitored_endpoints} endpoint(s) are not currently monitored"
                )
        else:
            coverage_percentage = 0
            fail_reasons.append("No endpoints found in Red Canary")
            recommendations.append("Deploy Red Canary sensors to endpoints to enable monitoring coverage")

        return create_response(
            result={
                criteriaKey: coverage_valid,
                "totalEndpoints": total_endpoints,
                "monitoredEndpoints": monitored_endpoints,
                "unmonitoredEndpoints": unmonitored_endpoints,
                "coveragePercentage": coverage_percentage if total_endpoints > 0 else 0
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalEndpoints": total_endpoints,
                "monitoredEndpoints": monitored_endpoints,
                "unmonitoredEndpoints": unmonitored_endpoints,
                "coveragePercentage": coverage_percentage if total_endpoints > 0 else 0
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
