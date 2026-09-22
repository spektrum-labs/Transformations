"""
Transformation: isEPPLoggingEnabled
Vendor: Sophos  |  Category: Endpoint Security

Evaluates whether Sophos security event logging is enabled and retrievable for
the tenant, by inspecting the response from Sophos Central's SIEM feed
(GET /siem/v1/events).

The verdict is driven by whether Sophos returned any security events. Retrieved
events ARE log records, so their presence is direct evidence that logging is
working, rather than an inference from the API call succeeding. The feed carries
routine operational traffic (UpdateSuccess, MacHealth, UpdateRebootRequired)
that any live estate emits continuously - measured live at 200 events in 12
minutes on a 50-endpoint tenant - so an empty events feed for a tenant whose
endpoints are reporting is abnormal, not merely quiet.

Note the events feed differs from the alerts feed on this point: empty ALERTS is
expected and healthy (no security incidents). This transform must be wired to
/siem/v1/events, not /siem/v1/alerts.

Scope note: this proves Sophos is recording security events and exposing them
for collection. It does NOT prove the customer has connected their own SIEM to
that feed - Sophos does not report who consumes it.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Sophos", "category": "Endpoint Security"}
        }
    }


def evaluate(data):
    """Core evaluation logic.

    Sophos GET /siem/v1/events returns:
      { "has_more": bool, "items": [ {...event...} ], "next_cursor": str }
    Token-Service preprocessing may hand the transform the bare items list
    instead of the wrapper, so both shapes are accepted.
    """
    try:
        events = None
        feed_shape = None

        if isinstance(data, list):
            # Preprocessed down to the bare items array
            events = data
            feed_shape = "list"
        elif isinstance(data, dict):
            if "items" in data and isinstance(data.get("items"), list):
                events = data.get("items")
                feed_shape = "wrapper"
            elif "has_more" in data or "next_cursor" in data:
                # Recognisable SIEM envelope with no items key present
                events = []
                feed_shape = "wrapper"

        if feed_shape is None:
            # Unrecognised payload. Do NOT score this as a compliance failure -
            # we cannot tell whether logging is off or the collection went wrong.
            return {
                "isEPPLoggingEnabled": False,
                "dataProblem": True,
                "reason": "SIEM feed response not recognised - cannot determine logging state",
            }

        event_count = len(events)
        severities = {}
        for event in events:
            if isinstance(event, dict):
                key = str(event.get("severity", "unknown"))
                severities[key] = severities.get(key, 0) + 1

        # Retrieved events ARE log records, so their presence is direct evidence
        # that Sophos logging is working - not an inference from the call
        # succeeding. An empty feed is a real answer from Sophos ("no events"),
        # not a collection failure, and for a tenant with endpoints reporting in
        # it is abnormal: the feed carries routine operational traffic
        # (UpdateSuccess, MacHealth) that any live estate emits continuously.
        # A tenant with no endpoints at all fails isEPPEnabled first, so this
        # criterion is not the only signal in that case.
        return {
            "isEPPLoggingEnabled": event_count > 0,
            "eventsRetrieved": event_count,
            "severityBreakdown": severities,
        }
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "dataProblem": True, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
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
        data_problem = eval_result.get("dataProblem", False)
        extra_fields = {k: v for k, v in eval_result.items()
                        if k not in (criteriaKey, "error", "reason", "dataProblem")}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        api_errors = []

        if result_value:
            count = eval_result.get("eventsRetrieved", 0)
            pass_reasons.append(f"Sophos security event logging is active: {count} events retrieved from the Central SIEM feed")
            sev = eval_result.get("severityBreakdown") or {}
            if sev:
                pass_reasons.append(f"severityBreakdown: {sev}")
        elif data_problem:
            # Surface as a data-collection problem, not a posture verdict.
            reason = eval_result.get("reason") or eval_result.get("error") or "SIEM feed could not be read"
            api_errors.append(reason)
            fail_reasons.append(reason)
            recommendations.append("Verify the Sophos SIEM feed (/siem/v1/events) is reachable for this tenant")
        else:
            fail_reasons.append("No security events retrieved from the Sophos Central SIEM feed")
            recommendations.append("Confirm endpoints are reporting in to Sophos Central; a tenant with active endpoints should be emitting routine events")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            api_errors=api_errors,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
