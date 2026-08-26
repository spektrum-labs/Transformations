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


OFFLINE_KEYWORDS = ["offline", "not seen", "unreachable", "no contact", "connectivity"]


def record_mentions_offline(record):
    if not isinstance(record, dict):
        return False
    fields_to_check = []
    for key in ("message", "subject", "sourceName", "sourceType", "sourceConfigUid"):
        val = record.get(key)
        if isinstance(val, str):
            fields_to_check.append(val.lower())
    for text in fields_to_check:
        for kw in OFFLINE_KEYWORDS:
            if kw in text:
                return True
    return False


def transform(input):
    data, validation = extract_input(input)

    # Normalize into a flat list of "pages" (dicts with results), since the
    # captured response is a list of {cursor, results} pages.
    pages = []
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                pages.append(entry)
            elif isinstance(entry, list):
                pages.append({"results": entry})
    elif isinstance(data, dict):
        pages.append(data)
    else:
        pages = []

    all_alerts = []
    for page in pages:
        results = page.get("results") if isinstance(page, dict) else None
        if isinstance(results, list):
            for r in results:
                all_alerts.append(r)

    total_alerts = len(all_alerts)
    offline_alerts = [a for a in all_alerts if record_mentions_offline(a)]
    offline_count = len(offline_alerts)

    is_enabled = offline_count > 0

    sample_names = []
    for a in offline_alerts[:5]:
        name = a.get("sourceName") or a.get("subject") or a.get("message") or "unknown"
        sample_names.append(str(name))

    if is_enabled:
        pass_reasons = [
            f"Found {offline_count} of {total_alerts} alert record(s) referencing an offline/connectivity "
            f"condition (examples: {', '.join(sample_names)}), confirming a device-offline alerting policy "
            f"condition exists and has fired."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Scanned {total_alerts} alert record(s) across all fetched alert pages and found none whose "
            f"message/subject/sourceName referenced an offline or connectivity condition, so no evidence of "
            f"an active device-offline alerting policy condition was found."
        ]
        recommendations = [
            "Configure a policy condition (e.g. under Policy > Conditions > Offline) that alerts technicians "
            "when a device has been offline beyond a configured duration, and confirm it is enabled for the "
            "relevant device policies."
        ]

    result = {
        "isDeviceOfflineAlertingEnabled": is_enabled,
        "totalAlertsScanned": total_alerts,
        "offlineRelatedAlertCount": offline_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalAlertsScanned": total_alerts, "offlineRelatedAlertCount": offline_count},
        metadata={
            "transformationId": "isDeviceOfflineAlertingEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
