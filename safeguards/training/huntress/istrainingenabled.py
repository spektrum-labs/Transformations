"""
Transformation: isTrainingEnabled
Vendor: Huntress SAT (Curricula)
Category: Training / Awareness

Validates that the customer has training assignments configured in Huntress SAT.
Consumes /api/v1/accounts/{accountId}/assignments which returns a JSON:API list:

  {"data": [{"type": "assignments", "id": "...", "attributes": {name, status, startsAt, endsAt, ...}}, ...],
   "meta": {"page": {"total": N, ...}}}

Each assignment has a status: 'in-progress', 'completed', 'scheduled', 'draft', etc.
The safeguard passes when at least one assignment exists; the in-progress count
is reported as the active-training signal.
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
                "transformationId": "isTrainingEnabled",
                "vendor": "Huntress SAT",
                "category": "Training"
            }
        }
    }


def pull_jsonapi_items(data):
    """Pull a list of JSON:API items from raw envelope, preprocessed list, or single record."""
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
    criteriaKey = "isTrainingEnabled"

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

        assignments = pull_jsonapi_items(data)

        total = len(assignments)
        in_progress = 0
        completed = 0
        scheduled = 0
        draft = 0
        other = 0

        for a in assignments:
            if not isinstance(a, dict):
                continue
            attrs = a.get('attributes') if isinstance(a.get('attributes'), dict) else a
            status = str(attrs.get('status', '')).lower()
            if status == 'in-progress':
                in_progress += 1
            elif status == 'completed':
                completed += 1
            elif status == 'scheduled':
                scheduled += 1
            elif status == 'draft':
                draft += 1
            else:
                other += 1

        training_enabled = total > 0

        if training_enabled:
            pass_reasons.append(
                f"Training is enabled ({total} assignment(s): "
                f"{in_progress} in-progress, {completed} completed, "
                f"{scheduled} scheduled, {draft} draft)"
            )
            if in_progress == 0 and scheduled == 0:
                additional_findings.append(
                    "No assignments are currently in-progress or scheduled — "
                    "all training appears to be historical or in draft"
                )
        else:
            fail_reasons.append("No training assignments configured for this customer")
            recommendations.append(
                "Create at least one training assignment in Huntress SAT for the customer's learners"
            )

        return create_response(
            result={
                criteriaKey: training_enabled,
                "totalAssignments": total,
                "inProgressAssignments": in_progress,
                "completedAssignments": completed,
                "scheduledAssignments": scheduled,
                "draftAssignments": draft,
                "otherStatusAssignments": other
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalAssignments": total,
                "inProgressAssignments": in_progress,
                "completedAssignments": completed,
                "scheduledAssignments": scheduled
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
