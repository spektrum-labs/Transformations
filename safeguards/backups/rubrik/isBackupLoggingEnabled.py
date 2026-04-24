"""
Transformation: isBackupLoggingEnabled
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether backup activity events are present in the RSC activity series,
confirming that backup event logging is active and capturing job history.
"""
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
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupLoggingEnabled",
                "vendor": "Rubrik",
                "category": "Backup"
            }
        }
    }


def evaluate(data):
    try:
        activity_nodes = []
        raw_nodes = data.get("nodes", [])
        if isinstance(raw_nodes, list):
            for node in raw_nodes:
                if isinstance(node, dict) and "activitySeriesId" in node:
                    activity_nodes.append(node)
        if not activity_nodes:
            series_data = data.get("activitySeriesConnection", {})
            if isinstance(series_data, dict):
                raw_nodes = series_data.get("nodes", [])
                if isinstance(raw_nodes, list):
                    activity_nodes = raw_nodes

        total_events = len(activity_nodes)
        backup_events = [
            n for n in activity_nodes
            if isinstance(n, dict) and str(n.get("lastActivityType", "")).upper() == "BACKUP"
        ]
        backup_count = len(backup_events)
        is_logging = backup_count > 0

        recent_objects = []
        for evt in backup_events[:5]:
            obj = evt.get("objectName", "")
            if obj and obj not in recent_objects:
                recent_objects.append(obj)

        return {
            "isBackupLoggingEnabled": is_logging,
            "totalActivityEvents": total_events,
            "backupActivityEvents": backup_count,
            "recentBackupObjects": recent_objects
        }
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        findings = []
        if result_value:
            pass_reasons.append(
                "Backup logging is active: " +
                str(eval_result.get("backupActivityEvents", 0)) +
                " BACKUP activity event(s) found in RSC activity series"
            )
            obj_list = eval_result.get("recentBackupObjects", [])
            if obj_list:
                findings.append("Recently logged backup objects: " + ", ".join(obj_list))
        else:
            fail_reasons.append(
                "No BACKUP type activity events were found in the RSC activity series; "
                "backup logging cannot be confirmed"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Ensure backup jobs are running and that the RSC activity series is retaining "
                "BACKUP event history. Verify service account permissions include activity log read access."
            )
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={
                "totalActivityEvents": eval_result.get("totalActivityEvents", 0),
                "backupActivityEvents": eval_result.get("backupActivityEvents", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
