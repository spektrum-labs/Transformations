
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


def extract_items(data):
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    candidate = data.get("data")
    if isinstance(candidate, list):
        return candidate
    known_cols = ["id", "organizationId", "offline", "approvalStatus", "maintenance", "os"]
    present_cols = [k for k in known_cols if k in data and isinstance(data.get(k), list)]
    if present_cols:
        lengths = [len(data[k]) for k in present_cols]
        max_len = max(lengths) if lengths else 0
        if max_len == 0:
            return []
        items = []
        for i in range(max_len):
            item = {}
            for k in present_cols:
                col = data.get(k) or []
                item[k] = col[i] if i < len(col) else None
            items.append(item)
        return items
    return []


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) or isinstance(data, list) else {}

    items = extract_items(data)

    devices_with_maintenance = []
    for item in items:
        if not isinstance(item, dict):
            continue
        m = item.get("maintenance")
        if not isinstance(m, dict):
            continue
        enabled = m.get("enabled")
        status = m.get("status")
        is_active = bool(enabled) or (isinstance(status, str) and status.upper() not in ("", "NONE", "DISABLED", "OFF"))
        if not is_active and not m.get("start") and not m.get("end"):
            continue
        devices_with_maintenance.append((item, m))

    total_maintenance_devices = len(devices_with_maintenance)
    bounded_count = 0
    indefinite_count = 0
    indefinite_sample_ids = []
    for item, m in devices_with_maintenance:
        start = m.get("start")
        end = m.get("end")
        if start and end:
            bounded_count = bounded_count + 1
        else:
            indefinite_count = indefinite_count + 1
            dev_id = item.get("id")
            if dev_id is not None and len(indefinite_sample_ids) < 5:
                indefinite_sample_ids.append(dev_id)

    if total_maintenance_devices == 0:
        result = {
            "isMaintenanceModeTimeLimited": True,
            "totalMaintenanceDevices": 0,
            "boundedWindowCount": 0,
            "indefiniteWindowCount": 0,
        }
        pass_reasons = ["No devices currently in maintenance mode; there is no indefinite-suppression exposure to flag."]
        fail_reasons = []
        recommendations = []
    else:
        is_time_limited = indefinite_count == 0
        result = {
            "isMaintenanceModeTimeLimited": is_time_limited,
            "totalMaintenanceDevices": total_maintenance_devices,
            "boundedWindowCount": bounded_count,
            "indefiniteWindowCount": indefinite_count,
        }
        if is_time_limited:
            pass_reasons = [
                "All %d device(s) currently in maintenance mode report both maintenance.start and maintenance.end timestamps, confirming bounded windows." % total_maintenance_devices
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                "%d of %d device(s) in maintenance mode have no maintenance.end timestamp (indefinite suppression), e.g. device id(s): %s." % (
                    indefinite_count, total_maintenance_devices, str(indefinite_sample_ids)
                )
            ]
            recommendations = [
                "Configure a fixed end time for all maintenance windows so alert suppression cannot persist indefinitely."
            ]

    input_summary = {
        "totalDevicesScanned": len(items),
        "totalMaintenanceDevices": total_maintenance_devices,
        "boundedWindowCount": bounded_count,
        "indefiniteWindowCount": indefinite_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMaintenanceModeTimeLimited",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
