"""Transformation: isMDRLoggingEnabled — Red Canary MDR Logging / SIEM Forwarding Active"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    endpoints = data.get("data") or []
    meta = data.get("meta") or {}
    total_items = meta.get("total_items") or 0

    endpoints_with_telemetry = 0
    endpoints_checked = 0
    no_telemetry_samples = []

    for endpoint in endpoints:
        attrs = endpoint.get("attributes")
        if attrs is None:
            continue
        if not isinstance(attrs, dict):
            continue
        endpoints_checked = endpoints_checked + 1
        last_activity = attrs.get("last_activity_at")
        if last_activity is not None:
            endpoints_with_telemetry = endpoints_with_telemetry + 1
        else:
            hostname = attrs.get("hostname") or attrs.get("display_identifier") or "unknown"
            if len(no_telemetry_samples) < 3:
                no_telemetry_samples.append(hostname)

    # Determine logging status:
    # - If attributes were inspectable: require at least one endpoint with non-null last_activity_at
    # - If no attributes were inspectable (all records truncated): fall back to total_items > 0
    if endpoints_checked > 0:
        is_logging_enabled = total_items > 0 and endpoints_with_telemetry > 0
    else:
        is_logging_enabled = total_items > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_logging_enabled:
        if endpoints_checked > 0:
            pass_reasons.append(
                f"{endpoints_with_telemetry} of {endpoints_checked} inspected endpoints "
                f"(total enrolled: {total_items}) have a non-null last_activity_at field, "
                f"confirming active telemetry is being forwarded to the Red Canary MDR logging pipeline."
            )
        else:
            pass_reasons.append(
                f"{total_items} endpoints are enrolled in Red Canary MDR "
                f"(meta.total_items={total_items}), confirming the MDR logging service is active."
            )
    else:
        if total_items == 0:
            fail_reasons.append(
                "No endpoints are enrolled in Red Canary (meta.total_items=0). "
                "MDR logging cannot be confirmed without at least one enrolled and reporting endpoint."
            )
            recommendations.append(
                "Enroll endpoints in Red Canary MDR and verify sensor connectivity to enable "
                "telemetry collection and event forwarding to the SIEM pipeline."
            )
        else:
            sample_str = ", ".join(no_telemetry_samples) if no_telemetry_samples else "n/a"
            fail_reasons.append(
                f"All {endpoints_checked} inspected endpoints have last_activity_at=null, "
                f"indicating no active telemetry is being received by Red Canary "
                f"(total enrolled: {total_items}). "
                f"Sample endpoints with no telemetry: {sample_str}."
            )
            recommendations.append(
                "Verify the Red Canary sensor is installed, running, and able to reach the Red Canary "
                "cloud ingest endpoint. Check firewall rules that may block telemetry forwarding."
            )

    return create_response(
        result={
            "isMDRLoggingEnabled": is_logging_enabled,
            "totalEndpoints": total_items,
            "endpointsWithActiveTelemetry": endpoints_with_telemetry,
            "endpointsInspected": endpoints_checked,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalEndpoints": total_items,
            "endpointsInspected": endpoints_checked,
            "endpointsWithActiveTelemetry": endpoints_with_telemetry,
        },
        metadata={
            "transformationId": "isMDRLoggingEnabled",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
