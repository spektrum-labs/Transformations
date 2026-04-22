"""
Transformation: isMFALoggingEnabled
Vendor: Google  |  Category: IAM
Evaluates: Check if MFA/login audit logging is enabled by verifying that login activity events
are actively being recorded in the Google Workspace Reports API login audit log.
Passes if the items array contains recent login events, indicating audit logging is operational.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFALoggingEnabled", "vendor": "Google", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        total_events = len(items)
        mfa_event_count = 0
        login_event_count = 0
        unique_actors = []

        for item in items:
            actor = item.get("actor", {})
            actor_email = actor.get("email", "")
            if actor_email and actor_email not in unique_actors:
                unique_actors.append(actor_email)

            events = item.get("events", [])
            if not isinstance(events, list):
                events = []

            for event in events:
                event_name = event.get("name", "")
                if event_name:
                    login_event_count = login_event_count + 1
                    if "2sv" in event_name.lower() or "verification" in event_name.lower() or "mfa" in event_name.lower() or "challenge" in event_name.lower():
                        mfa_event_count = mfa_event_count + 1

        logging_enabled = total_events > 0

        return {
            "isMFALoggingEnabled": logging_enabled,
            "totalLoginEvents": total_events,
            "totalLoginEventCount": login_event_count,
            "mfaRelatedEventCount": mfa_event_count,
            "uniqueActorCount": len(unique_actors)
        }
    except Exception as e:
        return {"isMFALoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFALoggingEnabled"
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

        total_login_events = eval_result.get("totalLoginEvents", 0)
        total_login_event_count = eval_result.get("totalLoginEventCount", 0)
        mfa_related_event_count = eval_result.get("mfaRelatedEventCount", 0)
        unique_actor_count = eval_result.get("uniqueActorCount", 0)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(
                "Login audit logging is operational: " + str(total_login_events) +
                " login activity record(s) found in the Google Workspace Reports API"
            )
            pass_reasons.append(
                "Audit events captured for " + str(unique_actor_count) + " unique actor(s)"
            )
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append(
                    "No login activity events found in the Google Workspace Reports API audit log"
                )
            recommendations.append(
                "Verify that the Google Workspace Reports API (Admin SDK) is enabled and that the service account has the required audit.readonly scope authorized via Domain-Wide Delegation"
            )
            recommendations.append(
                "Ensure login audit logging is turned on under Admin Console > Reports > Audit > Login"
            )

        if mfa_related_event_count > 0:
            additional_findings.append(
                str(mfa_related_event_count) + " MFA/2SV related login event(s) detected in the audit log"
            )

        extra_fields = {
            "totalLoginEvents": total_login_events,
            "totalLoginEventCount": total_login_event_count,
            "mfaRelatedEventCount": mfa_related_event_count,
            "uniqueActorCount": unique_actor_count
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalLoginEvents": total_login_events, "uniqueActorCount": unique_actor_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
