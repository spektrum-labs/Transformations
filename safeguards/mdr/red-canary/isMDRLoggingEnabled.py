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

    total_enrolled = len(endpoints)
    active_logging_count = 0
    no_checkin_count = 0
    sample_active = []
    sample_inactive = []

    for ep in endpoints:
        attrs = ep.get("attributes") or {}
        last_checkin = attrs.get("last_checkin_time")
        last_activity = attrs.get("last_activity_at")
        hostname = attrs.get("hostname") or str(ep.get("id", "unknown"))

        if last_checkin or last_activity:
            active_logging_count = active_logging_count + 1
            if len(sample_active) < 3:
                sample_active.append(hostname)
        else:
            no_checkin_count = no_checkin_count + 1
            if len(sample_inactive) < 3:
                sample_inactive.append(hostname)

    # Use total_items from meta as the authoritative fleet count
    fleet_total = total_items if total_items > 0 else total_enrolled

    # Logging is enabled if: fleet has enrolled endpoints AND at least one has active telemetry
    is_logging_enabled = fleet_total > 0 and active_logging_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_logging_enabled:
        sample_str = ", ".join(sample_active) if sample_active else "none sampled"
        pass_reasons.append(
            f"{active_logging_count} of {total_enrolled} sampled endpoints (fleet total: {fleet_total}) "
            f"report active telemetry via non-null last_checkin_time or last_activity_at fields. "
            f"Sample active endpoints: {sample_str}. MDR logging/telemetry forwarding is confirmed active."
        )
        if no_checkin_count > 0:
            inactive_str = ", ".join(sample_inactive) if sample_inactive else "none sampled"
            pass_reasons.append(
                f"{no_checkin_count} endpoints have null last_checkin_time and last_activity_at "
                f"(sample: {inactive_str}) — these may be newly registered or decommissioned sensors."
            )
    else:
        if fleet_total == 0:
            fail_reasons.append(
                "No endpoints are enrolled in Red Canary (meta.total_items=0 and data array is empty). "
                "MDR logging cannot be confirmed without enrolled endpoints."
            )
            recommendations.append(
                "Enroll endpoints in Red Canary MDR and confirm sensor check-in to activate telemetry logging."
            )
        else:
            fail_reasons.append(
                f"{fleet_total} endpoints enrolled but none of {total_enrolled} sampled endpoints report "
                f"active telemetry — all have null last_checkin_time and last_activity_at. "
                f"Telemetry/logging pipeline may be broken or sensors may not be checking in."
            )
            recommendations.append(
                "Verify that Red Canary sensors are actively checking in and that telemetry forwarding is "
                "configured. Check endpoint sensor status in the Red Canary portal."
            )

    return create_response(
        result={
            "isMDRLoggingEnabled": is_logging_enabled,
            "totalEnrolledEndpoints": fleet_total,
            "activeLoggingEndpoints": active_logging_count,
            "inactiveEndpoints": no_checkin_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalItems": fleet_total,
            "sampledEndpoints": total_enrolled,
            "activeLoggingCount": active_logging_count,
            "noCheckinCount": no_checkin_count,
        },
        metadata={
            "transformationId": "isMDRLoggingEnabled",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
