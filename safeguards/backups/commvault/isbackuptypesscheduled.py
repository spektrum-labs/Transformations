"""
Transformation: isBackupTypesScheduled
Vendor: Commvault  |  Category: Backups
Evaluates: Whether backup plans include both Full and Incremental (or Differential)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTypesScheduled", "vendor": "Commvault", "category": "Backups"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        has_full = False
        has_incremental = False
        scheduled_plans = 0

        FULL_KEYWORDS = {"full", "full_backup", "synth_full", "synthetic_full"}
        INCR_KEYWORDS = {"incremental", "incr", "differential", "diff", "delta"}

        def check_schedule_entry(entry):
            """Extract backup type from a schedule entry."""
            backup_type = str(
                entry.get("backupType",
                entry.get("scheduleBackupLevel",
                entry.get("backupLevel", "")))
            ).lower()

            is_full = any(k in backup_type for k in FULL_KEYWORDS)
            is_incr = any(k in backup_type for k in INCR_KEYWORDS)
            return is_full, is_incr

        def scan_plan(plan_obj):
            nonlocal has_full, has_incremental, scheduled_plans
            plan_full = False
            plan_incr = False

            # Look for schedule arrays at various nesting depths
            schedules = (
                plan_obj.get("schedules", []) or
                plan_obj.get("schedule", []) or
                plan_obj.get("schedulePolicy", {}).get("schedules", []) or
                []
            )

            # Also check backup window / RPO schedules
            rpo = plan_obj.get("rpo", {})
            if isinstance(rpo, dict):
                schedules = schedules + rpo.get("backupWindow", []) + rpo.get("slaBackupWindow", [])

            for s in schedules:
                if not isinstance(s, dict):
                    continue
                is_f, is_i = check_schedule_entry(s)
                plan_full = plan_full or is_f
                plan_incr = plan_incr or is_i
                # Check nested schedule patterns
                for nested_key in ("scheduleFrequency", "backupOpts", "dataBackupOption"):
                    nested = s.get(nested_key, {})
                    if isinstance(nested, dict):
                        is_f2, is_i2 = check_schedule_entry(nested)
                        plan_full = plan_full or is_f2
                        plan_incr = plan_incr or is_i2

            if plan_full or plan_incr:
                scheduled_plans += 1
                has_full = has_full or plan_full
                has_incremental = has_incremental or plan_incr

        # Handle both list of plans and single plan
        plans = (
            data.get("plans") or
            data.get("planList") or
            []
        )

        if isinstance(plans, list) and len(plans) > 0:
            for plan in plans:
                summary = plan.get("summary", plan)
                scan_plan(summary)
                scan_plan(plan)
        else:
            # Single plan response
            scan_plan(data)
            plan_detail = data.get("plan", {})
            if isinstance(plan_detail, dict):
                scan_plan(plan_detail)

        result = has_full and has_incremental
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTypesScheduled"
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

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Commvault configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
