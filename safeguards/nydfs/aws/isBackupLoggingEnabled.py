"""
Transformation: isBackupLoggingEnabled
Vendor: AWS  |  Category: nydfs
Evaluates: Whether a CloudTrail trail is active and configured to capture AWS Backup API activity.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupLoggingEnabled", "vendor": "AWS", "category": "nydfs"}
        }
    }


def evaluate(data):
    try:
        trail_list = data.get("trailList", [])
        if not isinstance(trail_list, list):
            trail_list = []
        total_trails = len(trail_list)
        qualifying_trails = []
        non_qualifying_trails = []
        for trail in trail_list:
            trail_name = trail.get("Name", trail.get("TrailARN", "unknown"))
            is_logging = trail.get("IsLogging", False)
            has_cloudwatch = bool(trail.get("CloudWatchLogsLogGroupArn", ""))
            has_s3 = bool(trail.get("S3BucketName", ""))
            if is_logging and (has_cloudwatch or has_s3):
                qualifying_trails.append(trail_name)
            else:
                non_qualifying_trails.append(trail_name)
        is_enabled = len(qualifying_trails) > 0
        return {
            "isBackupLoggingEnabled": is_enabled,
            "totalTrails": total_trails,
            "qualifyingTrailCount": len(qualifying_trails),
            "nonQualifyingTrailCount": len(non_qualifying_trails),
            "qualifyingTrails": qualifying_trails,
            "nonQualifyingTrails": non_qualifying_trails
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total_trails = eval_result.get("totalTrails", 0)
        qualifying_count = eval_result.get("qualifyingTrailCount", 0)
        non_qualifying = eval_result.get("nonQualifyingTrails", [])
        qualifying = eval_result.get("qualifyingTrails", [])
        if result_value:
            pass_reasons.append("At least one CloudTrail trail is active and has a log destination configured.")
            pass_reasons.append("Qualifying trails found: " + str(qualifying_count) + " of " + str(total_trails) + " total.")
            if qualifying:
                additional_findings.append("Qualifying trails: " + ", ".join([str(t) for t in qualifying]))
        else:
            fail_reasons.append("No CloudTrail trail was found that is both logging and configured with a log destination (CloudWatch Logs or S3).")
            if total_trails == 0:
                fail_reasons.append("No CloudTrail trails are configured in this account/region.")
            else:
                fail_reasons.append("Total trails found: " + str(total_trails) + ", but none satisfy the IsLogging + log-destination requirement.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append("Enable CloudTrail in this region and configure log delivery to either an S3 bucket or a CloudWatch Logs log group. Ensure IsLogging is true for the trail.")
            if non_qualifying:
                additional_findings.append("Trails that do not qualify: " + ", ".join([str(t) for t in non_qualifying]))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalTrails": total_trails, "qualifyingTrailCount": qualifying_count, "isBackupLoggingEnabled": result_value}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
