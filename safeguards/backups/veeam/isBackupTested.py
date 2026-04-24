"""
Transformation: isBackupTested
Vendor: Veeam  |  Category: Backup
Evaluates: Whether recent backup job sessions have completed successfully, confirming backups
           have been executed and tested, based on GET /api/v1/sessions response.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "Veeam", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        sessions = data.get("data", [])
        if not isinstance(sessions, list):
            sessions = []
        total_sessions = len(sessions)
        success_states = ["Success", "success", "Succeeded", "succeeded", "Warning", "warning"]
        successful_sessions = []
        failed_sessions = []
        for session in sessions:
            result_state = session.get("result", {})
            if isinstance(result_state, dict):
                state_value = result_state.get("result", result_state.get("state", ""))
            else:
                state_value = str(result_state) if result_state else ""
            session_name = session.get("name", session.get("jobName", "Unknown"))
            if state_value in success_states:
                successful_sessions.append(session_name)
            else:
                failed_sessions.append(session_name + " (" + state_value + ")")
        success_count = len(successful_sessions)
        failed_count = len(failed_sessions)
        is_tested = success_count > 0
        score = 0
        if total_sessions > 0:
            score = (success_count * 100) // total_sessions
        return {
            "isBackupTested": is_tested,
            "totalSessions": total_sessions,
            "successfulSessionCount": success_count,
            "failedSessionCount": failed_count,
            "scoreInPercentage": score
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        total_sessions = eval_result.get("totalSessions", 0)
        success_count = eval_result.get("successfulSessionCount", 0)
        failed_count = eval_result.get("failedSessionCount", 0)
        score = eval_result.get("scoreInPercentage", 0)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(str(success_count) + " backup session(s) completed successfully out of " + str(total_sessions) + " total sessions")
            pass_reasons.append("Backup success rate: " + str(score) + "%")
            if failed_count > 0:
                additional_findings.append(str(failed_count) + " session(s) ended with non-success states")
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            elif total_sessions == 0:
                fail_reasons.append("No backup job sessions found — backups have not been run or recorded")
                recommendations.append("Run and complete at least one backup job to confirm backups are operational")
            else:
                fail_reasons.append("No successful backup sessions found (" + str(total_sessions) + " sessions total, all failed or non-successful)")
                recommendations.append("Investigate failed backup sessions and resolve underlying issues")
                recommendations.append("Ensure backup jobs complete successfully on their configured schedule")
        return create_response(
            result={criteriaKey: result_value, "totalSessions": total_sessions, "successfulSessionCount": success_count, "failedSessionCount": failed_count, "scoreInPercentage": score},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalSessions": total_sessions, "successfulSessionCount": success_count, "failedSessionCount": failed_count})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
