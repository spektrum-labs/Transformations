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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
        total_count = None
    elif isinstance(data, dict):
        items = data.get("items") or data.get("data") or []
        if not isinstance(items, list):
            items = []
        total_count = data.get("totalCount")
        if total_count is None:
            total_count = data.get("count")
    else:
        items = []
        total_count = None

    now_iso = datetime.utcnow().isoformat() + "Z"

    active_items = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        expired_dt = entry.get("expiredDateTime")
        is_active = True
        if expired_dt:
            try:
                date_part = expired_dt.split("T")[0]
                year_s, month_s, day_s = date_part.split("-")
                exp_date = datetime(int(year_s), int(month_s), int(day_s))
                if exp_date < datetime.utcnow():
                    is_active = False
            except Exception:
                is_active = True
        if is_active:
            active_items.append(entry)

    active_count = len(active_items)
    if total_count is None:
        total_count = len(items)

    transformation_errors = []

    if active_count > 0:
        types_seen = []
        for e in active_items:
            t = e.get("type")
            if t and t not in types_seen:
                types_seen.append(t)
        types_str = ", ".join(types_seen[:5]) if types_seen else "unspecified"
        pass_reasons = [
            f"Suspicious Object List (threatintel/suspiciousObjects) returned {len(items)} entries, "
            f"of which {active_count} are active (not expired). Observed indicator types: {types_str}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Suspicious Object List (threatintel/suspiciousObjects) returned {len(items)} entries and "
            f"0 active (non-expired) indicators, so no threat-intel watchlist entries are currently being monitored."
        ]
        recommendations = [
            "Populate the tenant's Suspicious Object List with active threat-intel indicators (IOCs) "
            "so matches against the fleet can be enforced and monitored."
        ]

    result = {
        "activeThreatIntelWatchlistCount": active_count,
        "totalWatchlistEntries": len(items),
    }

    input_summary = {
        "totalItemsInResponse": len(items),
        "activeCount": active_count,
        "reportedTotalCount": total_count,
    }

    metadata = {
        "transformationId": "activeThreatIntelWatchlistCount",
        "vendor": "Trend Micro XDR",
        "category": "epp",
        "evaluatedAt": now_iso,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
        transformation_errors=transformation_errors,
    )
