"""
Transformation: isPatchManagementEnabled
Vendor: Qualys
Category: Security / Attack Surface Management

Evaluates whether patch management is enabled by querying the Qualys
Host List VM Detection API filtered by is_patchable=1 and status=Fixed.
If any hosts with Fixed (patched) detections are returned, patch
management is considered enabled.

Expected response structure:
{
    "HOST_LIST_VM_DETECTION_OUTPUT": {
        "RESPONSE": {
            "DATETIME": "2026-03-19T16:53:03Z",
            "HOST_LIST": {              # absent when no patched hosts
                "HOST": [               # single dict or list
                    {
                        "ID": "12345",
                        "IP": "10.0.0.1",
                        "DNS": "host.example.com",
                        "DETECTION_LIST": {
                            "DETECTION": [
                                {
                                    "QID": "1234",
                                    "STATUS": "Fixed",
                                    "IS_PATCHABLE": "1"
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }
}
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break

    return data, {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
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
                "transformationId": "isPatchManagementEnabled",
                "vendor": "Qualys",
                "category": "Attack Surface Management"
            }
        }
    }


def extract_hosts(data):
    """Extract HOST list from HOST_LIST_VM_DETECTION_OUTPUT response."""
    response = {}
    if isinstance(data, dict):
        output = data.get("HOST_LIST_VM_DETECTION_OUTPUT", data)
        response = output.get("RESPONSE", output)

    host_list = response.get("HOST_LIST", None)
    if host_list is None:
        return [], response.get("DATETIME", "")

    hosts = host_list.get("HOST", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    return hosts, response.get("DATETIME", "")


def count_detections(hosts):
    """Count total patchable detections across all hosts."""
    total = 0
    for host in hosts:
        detection_list = host.get("DETECTION_LIST", {})
        if not detection_list:
            continue
        detections = detection_list.get("DETECTION", [])
        if isinstance(detections, dict):
            detections = [detections]
        total = total + len(detections)
    return total


def transform(input):
    criteriaKey = "isPatchManagementEnabled"

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
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))]
            )

        # Check for integration execution errors
        if isinstance(data, dict) and "error" in data and "message" in data:
            if isinstance(data["message"], str) and data["message"].startswith("Integration execution error"):
                return create_response(
                    result={criteriaKey: False},
                    validation=validation,
                    fail_reasons=["Error communicating with Qualys API"],
                    recommendations=["Verify the Qualys API credentials and base URL are correct"]
                )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        hosts, response_datetime = extract_hosts(data)
        host_count = len(hosts)
        detection_count = count_detections(hosts)

        is_enabled = host_count > 0

        if is_enabled:
            pass_reasons.append(
                f"Patch management is enabled - {host_count} host(s) with {detection_count} patched (Fixed) detection(s) found"
            )
        else:
            fail_reasons.append(
                "No patched hosts found - no vulnerabilities with status Fixed were returned"
            )
            recommendations.append(
                "Verify that Qualys VM/VMDR is configured and that patches are being deployed to remediate detected vulnerabilities"
            )

        additional_findings = []
        if host_count > 0:
            statuses = {}
            for host in hosts:
                detection_list = host.get("DETECTION_LIST", {})
                if not detection_list:
                    continue
                detections = detection_list.get("DETECTION", [])
                if isinstance(detections, dict):
                    detections = [detections]
                for det in detections:
                    status = det.get("STATUS", "Unknown")
                    count = statuses.get(status, 0)
                    statuses[status] = count + 1

            for status_name in statuses:
                additional_findings.append({
                    "metric": f"patchableDetections_{status_name}",
                    "value": statuses[status_name],
                    "reason": f"{statuses[status_name]} patchable detection(s) with status '{status_name}'"
                })

        return create_response(
            result={
                criteriaKey: is_enabled,
                "hostCount": host_count,
                "patchedDetectionCount": detection_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "responseDateTime": response_datetime,
                "hostCount": host_count,
                "patchedDetectionCount": detection_count,
                "hasHostList": host_count > 0
            }
        )

    except json.JSONDecodeError as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [f"Invalid JSON: {str(e)}"], "warnings": []},
            fail_reasons=["Could not parse input as valid JSON"]
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
