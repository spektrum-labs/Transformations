"""
Transformation: isTrainingEnabled
Vendor: Huntress SAT (Curricula)
Category: Training / Awareness

Validates that security awareness training assignments are active and running.
Checks the assignments endpoint for configured training campaigns.
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
                "transformationId": "isTrainingEnabled",
                "vendor": "Huntress SAT",
                "category": "Training"
            }
        }
    }


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

        training_enabled = False
        total_assignments = 0
        active_assignments = 0

        assignments = []

        if isinstance(data, dict):
            if 'assignments' in data and isinstance(data['assignments'], list):
                assignments = data['assignments']
            elif 'data' in data and isinstance(data['data'], list):
                assignments = data['data']
        elif isinstance(data, list):
            assignments = data

        total_assignments = len(assignments)

        if total_assignments > 0:
            # Check for active/in-progress assignments
            for assignment in assignments:
                if isinstance(assignment, dict):
                    status = str(assignment.get('status', '')).lower()
                    state = str(assignment.get('state', '')).lower()
                    if status in ('active', 'in_progress', 'open', 'started') or \
                       state in ('active', 'in_progress', 'open', 'started'):
                        active_assignments += 1
                    elif not status and not state:
                        # No status field means likely active
                        active_assignments += 1

            if active_assignments > 0:
                training_enabled = True
            else:
                # Assignments exist but none are active - still consider enabled
                training_enabled = True
                additional_findings.append(f"All {total_assignments} assignments may be completed or inactive")

        if training_enabled:
            reason = f"Security awareness training is enabled ({total_assignments} assignment(s) found"
            if active_assignments > 0:
                reason += f", {active_assignments} active)"
            else:
                reason += ")"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("No training assignments found")
            recommendations.append("Configure security awareness training assignments in Huntress SAT")

        return create_response(
            result={
                criteriaKey: training_enabled,
                "totalAssignments": total_assignments,
                "activeAssignments": active_assignments
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalAssignments": total_assignments,
                "activeAssignments": active_assignments
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
