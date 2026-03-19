"""
Transformation: asm_transform
Vendor: Qualys
Category: Security / Attack Surface Management

Transforms Attack Surface Management data to check if ASM is enabled and logging.

Handles two response formats:
1. SCHEDULED_SCAN_LIST_OUTPUT - from getScheduledScans API
2. HOST_LIST_VM_DETECTION_OUTPUT - from getVulnerabilities/getPatchableDetections API
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
                "transformationId": "asm_transform",
                "vendor": "Qualys",
                "category": "Attack Surface Management"
            }
        }
    }


def check_scheduled_scans(data):
    """Check SCHEDULED_SCAN_LIST_OUTPUT for ASM enabled/logging status."""
    scan_output = data.get("SCHEDULED_SCAN_LIST_OUTPUT", {})
    response = scan_output.get("RESPONSE", {})
    scan_list = response.get("SCHEDULED_SCAN_LIST", {})
    scans = scan_list.get("SCAN", [])

    if isinstance(scans, dict):
        scans = [scans]

    has_scans = len(scans) > 0 if scans else False
    return has_scans, has_scans, len(scans) if scans else 0


def check_vm_detections(data):
    """Check HOST_LIST_VM_DETECTION_OUTPUT for detection activity."""
    output = data.get("HOST_LIST_VM_DETECTION_OUTPUT", {})
    response = output.get("RESPONSE", {})
    host_list = response.get("HOST_LIST", None)

    if host_list is None:
        return False, False, 0, 0

    hosts = host_list.get("HOST", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    host_count = len(hosts)
    detection_count = 0
    for host in hosts:
        detection_list = host.get("DETECTION_LIST", {})
        if not detection_list:
            continue
        detections = detection_list.get("DETECTION", [])
        if isinstance(detections, dict):
            detections = [detections]
        detection_count = detection_count + len(detections)

    has_hosts = host_count > 0
    has_detections = detection_count > 0
    return has_hosts, has_detections, host_count, detection_count


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isASMEnabled": False, "isASMLoggingEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Check for integration execution errors
        if isinstance(data, dict) and "error" in data and "message" in data:
            if isinstance(data["message"], str) and data["message"].startswith("Integration execution error"):
                return create_response(
                    result={"isASMEnabled": False, "isASMLoggingEnabled": False},
                    validation=validation,
                    fail_reasons=["Error communicating with Qualys API"],
                    recommendations=["Verify the Qualys API credentials and base URL are correct"]
                )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        default_value = data is not None

        if isinstance(data, dict) and "errors" in data:
            default_value = False

        is_asm_enabled = False
        is_asm_logging_enabled = False
        scan_count = 0

        if isinstance(data, dict):
            # Check explicit flags first
            is_asm_enabled = data.get("isASMEnabled", False)
            is_asm_logging_enabled = data.get("isASMLoggingEnabled", False)

            # Check SCHEDULED_SCAN_LIST_OUTPUT response
            if "SCHEDULED_SCAN_LIST_OUTPUT" in data:
                scans_enabled, scans_logging, scan_count = check_scheduled_scans(data)
                if scans_enabled:
                    is_asm_enabled = True
                if scans_logging:
                    is_asm_logging_enabled = True

            # Check HOST_LIST_VM_DETECTION_OUTPUT response
            if "HOST_LIST_VM_DETECTION_OUTPUT" in data:
                has_hosts, has_detections, host_count, detection_count = check_vm_detections(data)
                if has_hosts:
                    is_asm_enabled = True
                if has_detections:
                    is_asm_logging_enabled = True

            # Fallback to default if no specific response format matched
            if not is_asm_enabled and "SCHEDULED_SCAN_LIST_OUTPUT" not in data and "HOST_LIST_VM_DETECTION_OUTPUT" not in data:
                is_asm_enabled = data.get("isASMEnabled", default_value)
                is_asm_logging_enabled = data.get("isASMLoggingEnabled", default_value)

        additional_findings = []

        if is_asm_enabled:
            pass_reasons.append("Attack Surface Management is enabled")
        else:
            fail_reasons.append("Attack Surface Management is not enabled")
            recommendations.append("Enable Attack Surface Management for visibility into your external attack surface")

        if is_asm_logging_enabled:
            additional_findings.append({
                "metric": "isASMLoggingEnabled",
                "status": "pass",
                "reason": "ASM logging is enabled"
            })
        else:
            additional_findings.append({
                "metric": "isASMLoggingEnabled",
                "status": "fail",
                "reason": "ASM logging is not enabled",
                "recommendation": "Enable ASM logging for audit and compliance"
            })

        return create_response(
            result={
                "isASMEnabled": is_asm_enabled,
                "isASMLoggingEnabled": is_asm_logging_enabled
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "asmEnabled": is_asm_enabled,
                "asmLoggingEnabled": is_asm_logging_enabled
            }
        )

    except Exception as e:
        return create_response(
            result={"isASMEnabled": False, "isASMLoggingEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
