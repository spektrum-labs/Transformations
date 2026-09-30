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
        plans = data
    elif isinstance(data, dict):
        plans = data.get("data") or data.get("apiResponse") or []
        if not isinstance(plans, list):
            plans = []
    else:
        plans = []

    total_plans = len(plans)
    enabled_plans = [p for p in plans if isinstance(p, dict) and p.get("is_enabled")]
    total_enabled = len(enabled_plans)

    configured_plans = []
    unconfigured_plans = []
    for p in enabled_plans:
        schedule_info = p.get("schedule_info") or {}
        notification_setting = schedule_info.get("send_email_notification") or "NEVER"
        plan_name = p.get("name") or p.get("id") or "unknown"
        if notification_setting != "NEVER":
            configured_plans.append((plan_name, notification_setting))
        else:
            unconfigured_plans.append(plan_name)

    verdict = total_enabled > 0 and len(unconfigured_plans) == 0

    input_summary = {
        "totalPlans": total_plans,
        "enabledPlans": total_enabled,
        "configuredPlans": len(configured_plans),
        "unconfiguredPlans": len(unconfigured_plans),
    }

    if total_enabled == 0:
        return create_response(
            result={
                "isPolicyFailureNotificationConfigured": verdict,
                "totalPlans": total_plans,
                "enabledPlans": total_enabled,
            },
            validation=validation,
            fail_reasons=[
                "No enabled backup plans were found (total_plans=%d), so no failure notification configuration could be evaluated." % total_plans
            ],
            recommendations=[
                "Enable at least one backup plan and configure schedule_info.send_email_notification to alert on failure."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "isPolicyFailureNotificationConfigured", "vendor": "IDrive", "category": "backup"},
        )

    if verdict:
        details = ", ".join(["%s=%s" % (n, s) for n, s in configured_plans])
        return create_response(
            result={
                "isPolicyFailureNotificationConfigured": verdict,
                "totalPlans": total_plans,
                "enabledPlans": total_enabled,
            },
            validation=validation,
            pass_reasons=[
                "All %d enabled backup plan(s) have schedule_info.send_email_notification set to a non-NEVER value: %s." % (total_enabled, details)
            ],
            input_summary=input_summary,
            metadata={"transformationId": "isPolicyFailureNotificationConfigured", "vendor": "IDrive", "category": "backup"},
        )
    else:
        return create_response(
            result={
                "isPolicyFailureNotificationConfigured": verdict,
                "totalPlans": total_plans,
                "enabledPlans": total_enabled,
            },
            validation=validation,
            fail_reasons=[
                "%d of %d enabled backup plan(s) have schedule_info.send_email_notification set to NEVER: %s." % (
                    len(unconfigured_plans), total_enabled, ", ".join(unconfigured_plans)
                )
            ],
            recommendations=[
                "Set schedule_info.send_email_notification to ON_FAILURE (or equivalent) for plan(s): %s." % ", ".join(unconfigured_plans)
            ],
            input_summary=input_summary,
            metadata={"transformationId": "isPolicyFailureNotificationConfigured", "vendor": "IDrive", "category": "backup"},
        )
