"""Transformation: isDNSLoggingEnabled — DNS query logging active check for DNSFilter."""
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

    inner = data.get("data") or {}
    inner = inner if isinstance(inner, dict) else {}

    values = inner.get("values") or []
    values = values if isinstance(values, list) else []

    page = inner.get("page") or {}
    page = page if isinstance(page, dict) else {}

    total_logs = page.get("total")
    if total_logs is None:
        total_logs = 0
    try:
        total_logs = int(total_logs)
    except (TypeError, ValueError):
        total_logs = 0

    org_name = inner.get("organization_name") or "unknown"
    sample_count = len(values)

    logging_enabled = total_logs > 0 or sample_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if logging_enabled:
        pass_reasons.append(
            f"DNS query logging is active for organization '{org_name}': "
            f"{total_logs} total log entries recorded (page.total={total_logs}, "
            f"current page contains {sample_count} entries). "
            "A non-zero log count confirms that DNS queries are being captured and stored."
        )
    else:
        fail_reasons.append(
            f"No DNS query log entries found for organization '{org_name}' "
            f"(page.total={total_logs}, values returned={sample_count}). "
            "The getQueryLogs endpoint returned an empty result set, indicating "
            "that DNS query logging may not be active or no queries have been processed."
        )
        recommendations.append(
            "Verify that the DNSFilter deployment is actively routing DNS traffic "
            "for this organization. Ensure at least one network, site, or roaming client "
            "is connected and generating DNS queries through DNSFilter."
        )

    return create_response(
        result={
            "isDNSLoggingEnabled": logging_enabled,
            "totalLogEntries": total_logs,
            "currentPageEntries": sample_count,
            "organizationName": org_name,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalLogEntries": total_logs,
            "currentPageEntries": sample_count,
            "organizationName": org_name,
        },
        metadata={
            "transformationId": "isDNSLoggingEnabled",
            "vendor": "DNSFilter",
            "category": "networksecurity",
        },
    )
