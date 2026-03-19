"""
Transformation: isControlMonitoringEnabled
Vendor: ZenGRC  |  Category: GRC
Evaluates: Whether controls are defined, mapped to frameworks, and have active monitoring or assessment schedules.
Source: GET /api/v2/controls
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isControlMonitoringEnabled", "vendor": "ZenGRC", "category": "GRC"}
        }
    }


def evaluate(data):
    """Check if controls are defined with monitoring or assessment schedules."""
    try:
        controls = data.get("data", data.get("controls", data.get("results", [])))
        if not isinstance(controls, list):
            controls = [controls] if controls else []

        total_controls = len(controls)
        active_controls = 0
        controls_with_assessments = 0
        controls_mapped_to_frameworks = 0

        for control in controls:
            if not isinstance(control, dict):
                continue

            attrs = control.get("attributes", control)
            if not isinstance(attrs, dict):
                continue

            status = attrs.get("status", attrs.get("state", ""))
            is_active = str(status).lower() in ("active", "effective", "implemented", "operative", "enabled", "")

            if is_active:
                active_controls = active_controls + 1

            # Check for assessment/verification schedule
            last_assessed = attrs.get("last_assessed_at", attrs.get("lastAssessedAt", attrs.get("verified_date", "")))
            assessment_frequency = attrs.get("frequency", attrs.get("assessment_frequency", attrs.get("verify_frequency", "")))
            if last_assessed or assessment_frequency:
                controls_with_assessments = controls_with_assessments + 1

            # Check framework mapping via relationships
            relationships = control.get("relationships", {})
            if isinstance(relationships, dict):
                objectives = relationships.get("objectives", relationships.get("regulations", relationships.get("standards", None)))
                if objectives:
                    controls_mapped_to_frameworks = controls_mapped_to_frameworks + 1

        has_controls = total_controls > 0
        has_monitoring = controls_with_assessments > 0 or active_controls > 0

        return {
            "isControlMonitoringEnabled": has_controls and has_monitoring,
            "totalControls": total_controls,
            "activeControls": active_controls,
            "controlsWithAssessments": controls_with_assessments,
            "controlsMappedToFrameworks": controls_mapped_to_frameworks
        }
    except Exception as e:
        return {"isControlMonitoringEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isControlMonitoringEnabled"
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

        if result_value:
            pass_reasons.append(str(extra_fields.get("totalControls", 0)) + " controls defined in ZenGRC")
            pass_reasons.append(str(extra_fields.get("activeControls", 0)) + " controls are active")
            if extra_fields.get("controlsWithAssessments", 0) > 0:
                pass_reasons.append(str(extra_fields["controlsWithAssessments"]) + " controls have assessment schedules")
            if extra_fields.get("controlsMappedToFrameworks", 0) > 0:
                pass_reasons.append(str(extra_fields["controlsMappedToFrameworks"]) + " controls mapped to frameworks")
        else:
            if extra_fields.get("totalControls", 0) == 0:
                fail_reasons.append("No controls defined in ZenGRC")
                recommendations.append("Define controls and map them to compliance frameworks in ZenGRC")
            else:
                fail_reasons.append("Controls exist but no active monitoring or assessment schedules found")
                recommendations.append("Configure assessment schedules and activate control monitoring in ZenGRC")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalControls": extra_fields.get("totalControls", 0), "activeControls": extra_fields.get("activeControls", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
