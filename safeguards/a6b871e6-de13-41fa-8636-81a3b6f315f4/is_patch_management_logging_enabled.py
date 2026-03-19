"""
Transformation: isPatchManagementLoggingEnabled
Vendor: Qualys
Category: Security / Attack Surface Management

Evaluates whether patch management logging is enabled by querying the Qualys
Host List VM Detection API filtered by is_patchable=1 and status=Fixed.
If any hosts with Fixed (patched) detections containing DETECTION_LIST data
are returned, Qualys is actively logging patch remediation activity.

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
                                    "IS_PATCHABLE": "1",
                                    "LAST_UPDATE_DATETIME": "2026-03-18T10:00:00Z",
                                    "FIRST_FOUND_DATETIME": "2026-03-10T08:00:00Z"
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
                "transformationId": "isPatchManagementLoggingEnabled",
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


def count_hosts_with_detections(hosts):
    """Count hosts that have DETECTION_LIST data logged."""
    hosts_with_detections = 0
    total_detections = 0
    for host in hosts:
        detection_list = host.get("DETECTION_LIST", None)
        if not detection_list:
            continue
        detections = detection_list.get("DETECTION", [])
        if isinstance(detections, dict):
            detections = [detections]
        if len(detections) > 0:
            hosts_with_detections = hosts_with_detections + 1
            total_detections = total_detections + len(detections)
    return hosts_with_detections, total_detections


def transform(input):
    criteriaKey = "isPatchManagementLoggingEnabled"

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
        hosts_with_detections, total_detections = count_hosts_with_detections(hosts)

        logging_enabled = hosts_with_detections > 0

        if logging_enabled:
            pass_reasons.append(
                f"Patch management logging is enabled - {hosts_with_detections} host(s) with "
                f"{total_detections} logged patched (Fixed) detection(s)"
            )
        else:
            fail_reasons.append(
                "No patched detections are being logged - the response contained no HOST "
                "entries with Fixed detection data"
            )
            recommendations.append(
                "Ensure Qualys VM/VMDR scans are running regularly and that patches are being "
                "deployed so that Fixed detections are recorded and tracked over time"
            )

        return create_response(
            result={
                criteriaKey: logging_enabled,
                "hostsWithDetections": hosts_with_detections,
                "totalLoggedDetections": total_detections
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "responseDateTime": response_datetime,
                "totalHosts": host_count,
                "hostsWithDetections": hosts_with_detections,
                "totalLoggedDetections": total_detections,
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
