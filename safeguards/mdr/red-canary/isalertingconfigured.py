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


def section_was_read(section):
    """True when a triggers or playbooks section is a clean v3 collection (a data list, no error)."""
    if not isinstance(section, dict):
        return False
    if error_problem(section):
        return False
    return isinstance(section.get("data"), list)


def count_active(items):
    active = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("active") is True:
            active = active + 1
    return active


# ---- fail-closed guard (2026-10-01) ------------------------------------------------------------
# A body that does not show a measured answer proves nothing either way, so the criterion is
# returned as None with dataCollection.status "error". Token-Service reads that as Unevaluated:
# never a pass and never a finding. It covers a missing or empty body, a vendor or platform error
# envelope, a payload this transformation does not recognise, and a transformation exception.


def parse_body(data):
    """A JSON string or bytes body parsed; anything else unchanged. Unparseable text stays text."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except Exception:
            return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return data
    return data


def error_problem(data):
    """Describe why `data` is a vendor or platform error rather than evidence, or return None."""
    if data is None:
        return "Red Canary returned no body"
    if isinstance(data, (str, bytes)):
        return "Red Canary returned a body that is not JSON"
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus", "vendorStatus"):
        code = data.get(name)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Red Canary returned HTTP " + str(code)
    err = data.get("error") or data.get("errors") or data.get("vendorError")
    if err:
        if isinstance(err, list):
            err = err[0]
        if isinstance(err, dict):
            err = err.get("message") or err.get("detail") or err.get("title") or err.get("type") or "error"
        return "Red Canary returned an error: " + str(err)[:200]
    if str(data.get("status", "")).strip().lower() == "error":
        return "the integration reported an error status"
    return None


def unevaluated(keys, problem, validation=None, input_summary=None, transformation_errors=None):
    """Every key as None plus a dataCollection error: reads Unevaluated, never True or False."""
    result = {}
    for key in keys:
        result[key] = None
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        transformation_errors=transformation_errors,
        input_summary=input_summary,
    )


def transform(input):
    criteriaKey = "isAlertingConfigured"

    try:
        extracted = extract_input(parse_body(input))
        data = extracted.get("data")
        validation = extracted.get("validation")

        problem = error_problem(data)
        if problem:
            return unevaluated([criteriaKey], problem, validation)
        if not isinstance(data, dict) or ("triggers" not in data and "playbooks" not in data):
            return unevaluated([criteriaKey],
                               "The response carries neither the triggers nor the playbooks read: "
                               "nothing was measured", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        triggers = get_items_from_section(data.get("triggers"))
        playbooks = get_items_from_section(data.get("playbooks"))

        total_triggers = len(triggers)
        total_playbooks = len(playbooks)

        # A configured trigger or playbook is evidence on its own. "None configured" is only a
        # measurement when BOTH reads came back as clean collections; a missing, failed or
        # unrecognised section leaves the answer Unevaluated rather than a finding.
        if total_triggers == 0 and total_playbooks == 0:
            unread = []
            for name in ("triggers", "playbooks"):
                if not section_was_read(data.get(name)):
                    unread.append(name)
            if unread:
                return unevaluated([criteriaKey],
                                   "No triggers or playbooks were returned and the " + " and ".join(unread)
                                   + " read did not return a collection: nothing was measured",
                                   validation)
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
        message = "Transformation error: " + str(e)[:200]
        return unevaluated([criteriaKey], message, {"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[message])
