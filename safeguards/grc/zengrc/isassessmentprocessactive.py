"""
Transformation: isAssessmentProcessActive
Vendor: ZenGRC  |  Category: GRC
Evaluates: Whether vendor or control assessments are actively being conducted with defined criteria and completion tracking.
Source: GET /api/v2/assessments
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAssessmentProcessActive", "vendor": "ZenGRC", "category": "GRC"}
        }
    }


def evaluate(data):
    """Check if assessments are actively conducted with criteria and tracking."""
    try:
        assessments = data.get("data", data.get("assessments", data.get("results", [])))
        if not isinstance(assessments, list):
            assessments = [assessments] if assessments else []

        total_assessments = len(assessments)
        active_assessments = 0
        completed_assessments = 0
        assessments_with_criteria = 0
        assessment_types = []

        for assessment in assessments:
            if not isinstance(assessment, dict):
                continue

            attrs = assessment.get("attributes", assessment)
            if not isinstance(attrs, dict):
                continue

            status = str(attrs.get("status", attrs.get("state", attrs.get("assessment_status", "")))).lower()
            title = attrs.get("title", attrs.get("name", attrs.get("slug", "")))
            assessment_type = attrs.get("assessment_type", attrs.get("assessmentType", attrs.get("type", "")))

            if status in ("in progress", "active", "in_progress", "started", "open", "not started", "not_started", "draft"):
                active_assessments = active_assessments + 1
            elif status in ("completed", "closed", "finished", "done", "submitted"):
                completed_assessments = completed_assessments + 1
            else:
                # Treat unrecognized status as active
                if title:
                    active_assessments = active_assessments + 1

            # Check for assessment criteria / questions
            relationships = assessment.get("relationships", {})
            if isinstance(relationships, dict):
                questions = relationships.get("assessment_questions", relationships.get("questions", relationships.get("criteria", None)))
                if questions:
                    assessments_with_criteria = assessments_with_criteria + 1

            if assessment_type and str(assessment_type) not in assessment_types:
                assessment_types.append(str(assessment_type))

        has_assessment_activity = active_assessments > 0 or completed_assessments > 0

        return {
            "isAssessmentProcessActive": has_assessment_activity,
            "totalAssessments": total_assessments,
            "activeAssessments": active_assessments,
            "completedAssessments": completed_assessments,
            "assessmentsWithCriteria": assessments_with_criteria,
            "assessmentTypes": assessment_types[:10]
        }
    except Exception as e:
        return {"isAssessmentProcessActive": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAssessmentProcessActive"
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
            pass_reasons.append(str(extra_fields.get("totalAssessments", 0)) + " assessment(s) found in ZenGRC")
            if extra_fields.get("activeAssessments", 0) > 0:
                pass_reasons.append(str(extra_fields["activeAssessments"]) + " assessment(s) currently active")
            if extra_fields.get("completedAssessments", 0) > 0:
                pass_reasons.append(str(extra_fields["completedAssessments"]) + " assessment(s) completed")
            if extra_fields.get("assessmentTypes"):
                pass_reasons.append("Assessment types: " + ", ".join(extra_fields["assessmentTypes"][:5]))
        else:
            fail_reasons.append("No assessments found in ZenGRC")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create vendor or control assessments in ZenGRC")
            recommendations.append("Define assessment criteria and establish a regular assessment schedule")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalAssessments": extra_fields.get("totalAssessments", 0), "activeAssessments": extra_fields.get("activeAssessments", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
