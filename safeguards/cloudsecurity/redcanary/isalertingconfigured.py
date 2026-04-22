"""
Transformation: isAlertingConfigured
Vendor: Red Canary
Category: Cloud Security / Alerting

Validates that alerting is configured by checking for the existence of
automation triggers and playbooks. The input contains merged responses
from the triggers and playbooks automate APIs. If any triggers or
playbooks exist, alerting is considered configured.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return {"data": input_data.get("data"), "validation": input_data.get("validation")}
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data.get(key)
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return {"data": data, "validation": {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}}


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
                "transformationId": "isAlertingConfigured",
                "vendor": "Red Canary",
                "category": "Cloud Security"
            }
        }
    }


def get_items_from_section(section):
    if not isinstance(section, dict):
        return []
    items = section.get("data")
    if isinstance(items, list):
        return items
    return []


def count_active(items):
    active = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("active") is True:
            active = active + 1
    return active


def transform(input):
    criteriaKey = "isAlertingConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        extracted = extract_input(input)
        data = extracted.get("data")
        validation = extracted.get("validation")

        if validation.get("status") == "failed":
            has_data = isinstance(data, dict) and ('triggers' in data or 'playbooks' in data)
            if not has_data:
                return create_response(
                    result={criteriaKey: False},
                    validation=validation,
                    fail_reasons=["Input validation failed"]
                )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        triggers = []
        playbooks = []

        if isinstance(data, dict):
            triggers = get_items_from_section(data.get("triggers"))
            playbooks = get_items_from_section(data.get("playbooks"))

        total_triggers = len(triggers)
        total_playbooks = len(playbooks)
        active_triggers = count_active(triggers)
        active_playbooks = count_active(playbooks)

        alerting_configured = (total_triggers > 0) or (total_playbooks > 0)

        if alerting_configured:
            parts = []
            if total_triggers > 0:
                parts.append(f"{total_triggers} trigger(s) configured ({active_triggers} active)")
            if total_playbooks > 0:
                parts.append(f"{total_playbooks} playbook(s) configured ({active_playbooks} active)")
            pass_reasons.append("Alerting is configured: " + ", ".join(parts))

            if active_triggers == 0 and active_playbooks == 0:
                additional_findings.append("All triggers and playbooks are inactive")
        else:
            fail_reasons.append("No automation triggers or playbooks found")
            recommendations.append("Configure automation triggers and playbooks in Red Canary to enable alerting")

        return create_response(
            result={
                criteriaKey: alerting_configured,
                "totalTriggers": total_triggers,
                "activeTriggers": active_triggers,
                "totalPlaybooks": total_playbooks,
                "activePlaybooks": active_playbooks
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalTriggers": total_triggers,
                "activeTriggers": active_triggers,
                "totalPlaybooks": total_playbooks,
                "activePlaybooks": active_playbooks
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
