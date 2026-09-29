"""Transformation: isMDREnabled — Red Canary MDR enabled check via getEndpoints."""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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


#: share of enrolled endpoints Red Canary must report as monitored for MDR to count as configured
MDR_CONFIGURED_THRESHOLD = 95.0


def mdr_monitoring(endpoints):
    """(monitored, enrolled, reporting) over endpoints that are not decommissioned.

    Red Canary returns attributes.monitoring_status "monitored" or "unmonitored" per endpoint
    (booleans and counts can arrive as strings). An endpoint enrolled but not monitored, e.g.
    endpoint_status "suspended", is exactly the misconfiguration this measures.
    """
    monitored = 0
    enrolled = 0
    reporting = 0
    for ep in endpoints:
        attrs = ep.get("attributes") if isinstance(ep, dict) else None
        if not isinstance(attrs, dict):
            continue
        if str(attrs.get("is_decommissioned")).strip().lower() == "true":
            continue
        enrolled = enrolled + 1
        status = str(attrs.get("monitoring_status") or "").strip().lower()
        if status:
            reporting = reporting + 1
        if status == "monitored":
            monitored = monitored + 1
    return monitored, enrolled, reporting


def transform(input):
    data, validation = extract_input(input)

    if isinstance(data, list):
        endpoints = data
        meta = {}
        total_items = len(endpoints)
    elif isinstance(data, dict):
        endpoints = data.get("data") or []
        meta = data.get("meta") or {}
        try:
            total_items = int(str(meta.get("total_items")).strip())
        except (TypeError, ValueError):
            # absent or unreadable ("96" arrives as a string and used to raise on "> 0")
            total_items = len(endpoints)
    else:
        endpoints = []
        meta = {}
        total_items = 0

    page_count = len(endpoints)
    is_mdr_enabled = total_items > 0

    # isMDRConfigured is a measurement, not a copy of isMDREnabled: the share of enrolled
    # endpoints Red Canary is actually monitoring, judged against the threshold. Unanswered
    # (None) when no endpoint reports a monitoring_status, because then nothing was measured.
    monitored, enrolled, reporting = mdr_monitoring(endpoints)
    if reporting > 0 and enrolled > 0:
        monitored_pct = round(monitored * 100.0 / enrolled, 2)
        is_mdr_configured = monitored_pct >= MDR_CONFIGURED_THRESHOLD
    else:
        monitored_pct = None
        is_mdr_configured = None

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_mdr_enabled:
        pass_reasons.append(
            f"Red Canary MDR is active: meta.total_items={total_items} endpoint(s) are enrolled "
            f"in the tenant. {page_count} endpoint(s) returned on this page confirm the MDR "
            "service is connected and monitoring the environment."
        )
    else:
        fail_reasons.append(
            "Red Canary MDR returned 0 endpoints (meta.total_items=0). No endpoints are enrolled "
            "in this tenant, which indicates MDR monitoring is not active."
        )
        recommendations.append(
            "Enroll at least one endpoint in the Red Canary MDR platform to confirm the service "
            "is operating against the customer environment. Contact Red Canary support to verify "
            "tenant connectivity and sensor deployment."
        )

    if is_mdr_configured is True:
        pass_reasons.append(
            f"Red Canary MDR is configured: {monitored} of {enrolled} enrolled endpoint(s) are monitored "
            f"({monitored_pct}%, threshold {MDR_CONFIGURED_THRESHOLD}%)."
        )
    elif is_mdr_configured is False:
        fail_reasons.append(
            f"Red Canary MDR is not fully configured: {monitored} of {enrolled} enrolled endpoint(s) are "
            f"monitored ({monitored_pct}%, threshold {MDR_CONFIGURED_THRESHOLD}%); "
            f"{enrolled - monitored} are enrolled but unmonitored."
        )
        recommendations.append(
            "Return the unmonitored endpoints to monitoring in the Red Canary portal (Endpoints, filter "
            "monitoring status: unmonitored), or decommission those no longer in service."
        )
    else:
        fail_reasons.append(
            "isMDRConfigured not measured: no endpoint in the response reports a monitoring_status."
        )

    return create_response(
        result={
            "isMDREnabled": is_mdr_enabled,
            "isMDRConfigured": is_mdr_configured,
            "mdrMonitoredPercentage": monitored_pct,
            "mdrMonitoredEndpoints": monitored,
            "mdrEnrolledEndpoints": enrolled,
            "totalEndpoints": total_items,
            "pageEndpoints": page_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalEndpoints": total_items,
            "pageEndpoints": page_count,
            "metaApiVersion": meta.get("api_version"),
        },
        metadata={
            "transformationId": "isMDREnabled",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
