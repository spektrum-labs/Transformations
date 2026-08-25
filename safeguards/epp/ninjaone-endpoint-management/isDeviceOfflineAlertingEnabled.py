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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
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

    alerts = data.get("apiResponse")
    if alerts is None:
        alerts = data.get("data")
    if not isinstance(alerts, list):
        alerts = []

    offline_keywords = ["OFFLINE", "DEVICE_OFFLINE", "AGENT_OFFLINE"]

    offline_alerts = []
    source_types_seen = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        source_type = alert.get("sourceType") or ""
        message = alert.get("message") or ""
        source_types_seen.add(source_type)
        is_offline = False
        for kw in offline_keywords:
            if kw in source_type.upper():
                is_offline = True
                break
        if not is_offline and "offline" in message.lower():
            is_offline = True
        if is_offline:
            offline_alerts.append(alert)

    total_alerts = len(alerts)
    offline_count = len(offline_alerts)
    is_enabled = offline_count > 0

    input_summary = {
        "totalAlerts": total_alerts,
        "offlineAlertCount": offline_count,
        "distinctSourceTypes": len(source_types_seen),
    }

    if is_enabled:
        sample_uids = [a.get("uid") for a in offline_alerts[:3] if isinstance(a, dict)]
        pass_reasons = [
            f"Found {offline_count} of {total_alerts} alerts with an offline-device sourceType or "
            f"message (sample alert uids: {sample_uids}), indicating a policy condition for device "
            f"offline alerting is configured and has fired."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        distinct_list = sorted(source_types_seen)
        fail_reasons = [
            f"None of the {total_alerts} alerts returned by getAlerts had a sourceType or message "
            f"indicating a device-offline condition. Observed sourceTypes: {distinct_list}."
        ]
        recommendations = [
            "Configure a policy condition (e.g. CONDITION_OFFLINE / device offline monitoring) in "
            "NinjaOne to alert technicians when a device has been offline beyond a configured duration."
        ]

    result = {
        "isDeviceOfflineAlertingEnabled": is_enabled,
        "totalAlerts": total_alerts,
        "offlineAlertCount": offline_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isDeviceOfflineAlertingEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
