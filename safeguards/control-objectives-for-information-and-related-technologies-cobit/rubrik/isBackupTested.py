"""
Transformation: isBackupTested
Vendor: Rubrik  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Verifies that recent successful backup activity events exist
(lastActivityType: Backup, lastActivityStatus: Success) from the activitySeriesConnection,
confirming that backups have been executed and validated within the Rubrik Security Cloud
environment.
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
                "transformationId": "isBackupTested",
                "vendor": "Rubrik",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def extract_activity_connection(data):
    """
    Extract activitySeriesConnection from multiple possible data shapes.
    getRecentBackupActivity returnSpec: data = data.activitySeriesConnection
    So the transformation input 'data' field should be the activitySeriesConnection object
    with shape {count, nodes: [{id, lastActivityType, lastActivityStatus, ...}]}
    """
    if isinstance(data, dict):
        if "count" in data and "nodes" in data:
            return data
        inner = data.get("data", None)
        if isinstance(inner, dict) and "count" in inner and "nodes" in inner:
            return inner
        conn = data.get("activitySeriesConnection", None)
        if isinstance(conn, dict):
            return conn
        if isinstance(inner, dict):
            conn2 = inner.get("activitySeriesConnection", None)
            if isinstance(conn2, dict):
                return conn2
    return {}


def evaluate(data):
    """Core evaluation logic for isBackupTested."""
    try:
        conn = extract_activity_connection(data)
        count = conn.get("count", 0)
        nodes = conn.get("nodes", [])
        if not isinstance(nodes, list):
            nodes = []

        confirmed_successful = [
            n for n in nodes
            if n.get("lastActivityType", "") == "Backup"
            and n.get("lastActivityStatus", "") == "Success"
        ]
        confirmed_count = len(confirmed_successful)

        effective_count = count if count > 0 else confirmed_count

        sample_objects = []
        seen = {}
        for n in confirmed_successful:
            obj_name = n.get("objectName", "")
            if obj_name and obj_name not in seen:
                seen[obj_name] = True
                sample_objects.append(obj_name)
            if len(sample_objects) >= 5:
                break

        is_backup_tested = effective_count > 0

        return {
            "isBackupTested": is_backup_tested,
            "successfulBackupActivityCount": effective_count,
            "confirmedSuccessfulEvents": confirmed_count,
            "sampleBackedUpObjects": sample_objects
        }
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTested"
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
        additional_findings = []

        if result_value:
            pass_reasons.append(
                str(eval_result.get("successfulBackupActivityCount", 0)) +
                " recent successful backup activity event(s) confirmed in Rubrik Security Cloud"
            )
            sample = eval_result.get("sampleBackedUpObjects", [])
            if sample:
                additional_findings.append(
                    "Sample successfully backed-up objects: " + ", ".join(sample)
                )
        else:
            fail_reasons.append(
                "No recent successful backup activity events found "
                "(lastActivityType: Backup, lastActivityStatus: Success)"
            )
            recommendations.append(
                "Ensure backup jobs are running successfully. Review SLA Domain assignments and check for backup failures in the Rubrik Security Cloud activity log."
            )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        input_summary = {
            "successfulBackupActivityCount": eval_result.get("successfulBackupActivityCount", 0),
            "confirmedSuccessfulEvents": eval_result.get("confirmedSuccessfulEvents", 0)
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
