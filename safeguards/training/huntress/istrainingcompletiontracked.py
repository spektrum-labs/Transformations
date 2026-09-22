"""
Transformation: isTrainingCompletionTracked
Vendor: Huntress SAT (Curricula)
Category: Training / Completion Tracking

Validates that learners are enrolled in Huntress SAT for the customer.
Consumes /api/v1/accounts/{accountId}/learners which returns a JSON:API list:

  {"data": [{"type": "learners", "id": "...", "attributes": {firstName, lastName, email, status, ...}}, ...],
   "meta": {"page": {"total": N, ...}}}

Each learner has a status: 'active', 'deactivated', etc. The safeguard passes
when at least one active learner exists, since training completion is recorded
per learner once they are enrolled.
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
                "transformationId": "isTrainingCompletionTracked",
                "vendor": "Huntress SAT",
                "category": "Training"
            }
        }
    }


def pull_jsonapi_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get('data'), list):
            return data['data']
        if isinstance(data.get('data'), dict):
            return [data['data']]
        return [data]
    return []


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

        learners = pull_jsonapi_items(data)

        total = len(learners)
        active = 0
        deactivated = 0
        other = 0
        do_not_phish = 0

        for l in learners:
            if not isinstance(l, dict):
                continue
            attrs = l.get('attributes') if isinstance(l.get('attributes'), dict) else l
            status = str(attrs.get('status', '')).lower()
            if status == 'active':
                active += 1
            elif status == 'deactivated':
                deactivated += 1
            else:
                other += 1
            if attrs.get('doNotPhish'):
                do_not_phish += 1

        # Completion tracking requires at least one active learner — learners are
        # the records against which completion is recorded inside Curricula.
        completion_tracked = active > 0

        if completion_tracked:
            pass_reasons.append(
                f"Training completion tracking is in place: {active} active learner(s) enrolled "
                f"(of {total} total)"
            )
            if deactivated > 0:
                additional_findings.append(
                    f"{deactivated} learner(s) are deactivated and will not receive new training"
                )
        else:
            if total == 0:
                fail_reasons.append("No learners enrolled in Huntress SAT for this customer")
                recommendations.append(
                    "Add learners (users) to the customer's Huntress SAT account so training "
                    "completion can be tracked"
                )
            else:
                fail_reasons.append(
                    f"No active learners — all {total} enrolled learners are deactivated or in another non-active state"
                )
                recommendations.append("Re-activate learners to resume training completion tracking")

        return create_response(
            result={
                criteriaKey: completion_tracked,
                "totalLearners": total,
                "activeLearners": active,
                "deactivatedLearners": deactivated,
                "otherStatusLearners": other,
                "doNotPhishLearners": do_not_phish
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalLearners": total,
                "activeLearners": active,
                "deactivatedLearners": deactivated
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
