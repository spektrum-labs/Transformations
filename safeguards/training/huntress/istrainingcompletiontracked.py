"""
Transformation: isTrainingCompletionTracked
Vendor: Huntress SAT (Curricula)
Category: Training / Completion Tracking

Ensures training completion is tracked and learners are enrolled.
Checks the learners endpoint for enrolled users.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "isTrainingCompletionTracked",
                "vendor": "Huntress SAT",
                "category": "Training"
            }
        }
    }


def transform(input):
    criteriaKey = "isTrainingCompletionTracked"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        completion_tracked = False
        total_learners = 0
        completed_learners = 0

        learners = []

        if isinstance(data, dict):
            if 'learners' in data and isinstance(data['learners'], list):
                learners = data['learners']
            elif 'data' in data and isinstance(data['data'], list):
                learners = data['data']
            elif 'total' in data or 'total_count' in data:
                # Paginated response with count only
                total_learners = data.get('total', data.get('total_count', 0))
                if total_learners > 0:
                    completion_tracked = True
        elif isinstance(data, list):
            learners = data

        if learners:
            total_learners = len(learners)

            for learner in learners:
                if isinstance(learner, dict):
                    status = str(learner.get('status', '')).lower()
                    completed = learner.get('completed', learner.get('is_completed', False))
                    progress = learner.get('progress', learner.get('completion_percentage', 0))

                    if completed or status == 'completed' or progress == 100:
                        completed_learners += 1

            if total_learners > 0:
                completion_tracked = True

        if completion_tracked:
            reason = f"Training completion is tracked ({total_learners} learner(s) enrolled"
            if completed_learners > 0:
                reason += f", {completed_learners} completed)"
            else:
                reason += ")"
            pass_reasons.append(reason)

            if total_learners > 0 and completed_learners == 0:
                additional_findings.append("No learners have completed training yet")
        else:
            fail_reasons.append("No learners enrolled in training")
            recommendations.append("Enroll users as learners in Huntress SAT to track training completion")

        completion_rate = 0
        if total_learners > 0:
            completion_rate = round((completed_learners / total_learners) * 100, 1)

        return create_response(
            result={
                criteriaKey: completion_tracked,
                "totalLearners": total_learners,
                "completedLearners": completed_learners,
                "completionRate": completion_rate
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalLearners": total_learners,
                "completedLearners": completed_learners,
                "completionRate": completion_rate
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
