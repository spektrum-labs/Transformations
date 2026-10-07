"""
Transformation: backupFrequency
Vendor: Azure Recovery Services / Azure Data Protection
Category: Backup / Data Protection

Evaluates whether backup policies meet a minimum daily frequency across all
Recovery Services vaults and Backup vaults in the subscription.

Data source: Azure Resource Graph query (getBackupSchedules) returning all
backup policies with scheduleType, scheduleTimes, scheduleDays, and hasSchedule
fields across all resource groups and vaults.
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
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
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get("backupFrequency") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["backupFrequency could not be measured from the response"]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else not_measured_reasons},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "backupFrequency", "vendor": "Azure", "category": "Backup"}
        }
    }


# Schedule types that meet or exceed daily frequency
DAILY_OR_BETTER = ['daily', 'hourly']


def evaluate(data):
    """Evaluate backup frequency across all policies from Resource Graph response.

    The Resource Graph query returns rows where each row is a packed 'result' dict
    containing: name, vaultName, resourceGroup, scheduleType, hasSchedule, etc.
    """
    try:
        if not isinstance(data, dict):
            return {"backupFrequency": None, "error": "Response is not an object; no backup policies to evaluate"}
        inner_data = data.get("data", data)
        if not isinstance(inner_data, dict):
            return {"backupFrequency": None, "error": "Response data is not an object; no backup policies to evaluate"}
        rows = inner_data.get("rows")

        if not isinstance(rows, list) or not rows:
            # Fallback: single-policy format (legacy per-vault listBackupPolicies response)
            props = data.get('properties')
            schedule = props.get('schedulePolicy') if isinstance(props, dict) else None
            freq_mins = schedule.get('scheduleFrequencyInMins') if isinstance(schedule, dict) else None
            if not isinstance(freq_mins, (int, float)) or isinstance(freq_mins, bool):
                # No policy rows and no schedulePolicy: nothing was measured. Resource Graph is
                # RBAC-scoped -- a partially readable scope answers 200 with only the readable
                # subset and, in Microsoft's words, "without any indication that the result might
                # be partial" -- so zero rows is not "none". See CONTRIBUTING.md, "Azure Resource
                # Graph: zero rows is not a proven empty set".
                return {"backupFrequency": None, "error": "No backup policy rows or schedulePolicy in the response"}
            meets_daily = freq_mins > 0 and freq_mins <= 1440
            return {"backupFrequency": meets_daily, "frequencyMinutes": freq_mins}

        policies_evaluated = 0
        policies_meeting_frequency = []
        policies_failing_frequency = []

        for row in rows:
            # Each row is a list (positional) or the packed 'result' dict
            if isinstance(row, list) and len(row) > 0:
                # The Resource Graph query packs all fields into a single 'result' column
                policy = row[0] if isinstance(row[0], dict) else {}
            elif isinstance(row, dict):
                policy = row
            else:
                continue

            policy_name = policy.get("name", "Unknown")
            vault_name = policy.get("vaultName", "Unknown")
            schedule_type = (policy.get("scheduleType") or "").lower()
            has_schedule = policy.get("hasSchedule", False)

            policies_evaluated += 1

            if has_schedule and schedule_type in DAILY_OR_BETTER:
                policies_meeting_frequency.append(f"{policy_name} ({vault_name}: {schedule_type})")
            else:
                policies_failing_frequency.append(f"{policy_name} ({vault_name}: {schedule_type or 'none'})")

        if policies_evaluated == 0:
            return {"backupFrequency": None, "error": "No readable backup policy rows in the response"}

        all_meet = len(policies_meeting_frequency) > 0 and policies_evaluated > 0

        return {
            "backupFrequency": all_meet,
            "policiesEvaluated": policies_evaluated,
            "policiesMeetingFrequency": len(policies_meeting_frequency),
            "policiesFailingFrequency": policies_failing_frequency
        }
    except Exception as e:
        return {"backupFrequency": None, "error": str(e)}


def transform(input):
    """Evaluates whether all Azure backup policies meet daily minimum frequency."""
    criteriaKey = "backupFrequency"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: None}, validation=validation, fail_reasons=["Input validation failed"])

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value is None:
            fail_reasons.append(f"{criteriaKey} not evaluated: {eval_result.get('error', 'no backup policy data')}")
        elif result_value:
            pass_reasons.append(f"All {extra_fields.get('policiesEvaluated', 0)} backup policies meet daily or better frequency")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            failing = extra_fields.get("policiesFailingFrequency", [])
            if failing:
                fail_reasons.append(f"Policies not meeting daily frequency: {', '.join(failing[:5])}")
            recommendations.append("Configure all Azure backup policies to run at least daily")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"policiesEvaluated": extra_fields.get("policiesEvaluated", 0), "meetingFrequency": extra_fields.get("policiesMeetingFrequency", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
