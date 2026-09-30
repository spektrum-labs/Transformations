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

    plans = []
    if isinstance(data, list):
        plans = data
    elif isinstance(data, dict):
        candidate = data.get("data")
        if isinstance(candidate, list):
            plans = candidate
        else:
            candidate2 = data.get("backup_plan") or data.get("plans")
            if isinstance(candidate2, list):
                plans = candidate2
            else:
                plans = []

    total_plans = len(plans)

    pending_ids = []
    plan_device_ids = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue

        devices_list = plan.get("devices") or []
        if isinstance(devices_list, list):
            for dv in devices_list:
                if dv not in plan_device_ids:
                    plan_device_ids.append(dv)

        pending_list = plan.get("backup_pending_on") or []
        if isinstance(pending_list, list):
            for pid in pending_list:
                if pid not in pending_ids:
                    pending_ids.append(pid)

    unprotected_count = len(pending_ids)
    total_devices_in_plans = len(plan_device_ids)

    input_summary = {
        "totalBackupPlansScanned": total_plans,
        "totalDevicesAssignedToPlans": total_devices_in_plans,
        "totalPendingDeviceIds": unprotected_count,
    }

    if total_plans == 0:
        pass_reasons = []
        fail_reasons = [
            "No backup plan records were returned for this account, so backup-plan coverage cannot be confirmed."
        ]
        recommendations = [
            "Verify at least one backup plan is configured for this account."
        ]
    elif unprotected_count == 0:
        pass_reasons = [
            f"Scanned {total_plans} backup plan(s); none report entries in backup_pending_on, "
            f"and {total_devices_in_plans} device(s) are listed under plan 'devices' assignment. "
            f"unprotectedResourcesCount is 0."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{unprotected_count} device id(s) appear in backup_pending_on across {total_plans} backup plan(s) "
            f"(pending device ids: {pending_ids[:10]}), meaning a backup plan has not yet been applied to them."
        ]
        recommendations = [
            "Assign and apply a backup plan to the pending devices so they are actively protected."
        ]

    result = {
        "unprotectedResourcesCount": unprotected_count,
        "totalBackupPlansScanned": total_plans,
        "totalDevicesAssignedToPlans": total_devices_in_plans,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "unprotectedResourcesCount",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
