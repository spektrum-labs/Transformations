"""
Transformation: isAutoUpdateEnabled
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: Endpoint Security
Method: getPolicies (GET /nebula/v1/policies)

Evidence: `policies[].contents.policy.updates.pause_until` (documented in the Nebula OpenAPI
policy schema; example "2020-04-10T14:55:00+03:00", nullable).

ThreatDown's support article "Endpoint agent policy settings in Nebula" (updated 2026-09-16)
says agent updates are delivered automatically by a ring rollout, that Component Package
(protection engine) updates are ALWAYS automatic, and that the only admin control is "Pause
endpoint agent updates" (Windows only), which stops agent updates for up to 31 days and shows
the date and time updates will continue. That date is `updates.pause_until`.

Rule: the response holds at least one policy, every policy carries a `contents.policy` object,
and no policy has a `pause_until` later than the evaluation time. A missing or null
`pause_until` is read at its documented default (not paused). A `pause_until` that cannot be
parsed counts as paused. Every policy is judged, assigned or not.

Platform coverage: the pause exists only for Windows, so macOS and Linux endpoints cannot be
paused and have no field to be missing.

Proves: automatic ThreatDown agent and engine updates are not suspended by any Nebula policy.
Does not prove: that every endpoint has already installed the newest release (ring rollout),
or anything about devices ThreatDown does not manage.
"""
import json
from datetime import datetime, timezone


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAutoUpdateEnabled", "vendor": "ThreatDown", "category": "Endpoint Security"}
        }
    }


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "ThreatDown API returned an error")
    return None


def policy_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        policies = data.get("policies")
        if isinstance(policies, list):
            return policies
    return None


def parse_instant(value):
    """UTC-aware datetime, or None when unparseable."""
    try:
        text = str(value).strip()
        if text.endswith("Z") or text.endswith("z"):
            text = text[:-1] + "+00:00"
        when = datetime.fromisoformat(text)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when.astimezone(timezone.utc)
    except Exception:
        return None


def paused_reason(policy, now):
    """None when the policy does not pause updates, otherwise why it counts as paused."""
    contents = policy.get("contents")
    settings = contents.get("policy") if isinstance(contents, dict) else None
    if not isinstance(settings, dict):
        return "no policy contents in the response"
    updates = settings.get("updates")
    if updates is None:
        return None
    if not isinstance(updates, dict):
        return "update settings not recognised"
    until = updates.get("pause_until")
    if until is None or str(until).strip() == "":
        return None
    when = parse_instant(until)
    if when is None:
        return "pause_until not readable: " + str(until)[:40]
    if when > now:
        return "agent updates paused until " + when.isoformat()
    return None


def transform(input):
    criteriaKey = "isAutoUpdateEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        policies = policy_list(data)
        if error or policies is None:
            reason = error or "Policies response not recognised - no policies list present"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Verify GET /nebula/v1/policies is reachable with the accountid header"])

        now = datetime.now(timezone.utc)
        judged = [p for p in policies if isinstance(p, dict)]
        paused = []
        for policy in judged:
            reason = paused_reason(policy, now)
            if reason is not None:
                paused.append(str(policy.get("name") or policy.get("id") or "unnamed") + ": " + reason)
        value = len(judged) > 0 and len(paused) == 0

        summary = {
            "policiesJudged": len(judged),
            "policiesPausingUpdates": paused[:20],
        }
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if not judged:
            fail_reasons.append("No ThreatDown policies in the response")
            recommendations.append("Verify the Nebula account has at least one policy and the API client can read policies")
        elif value:
            pass_reasons.append(f"None of {len(judged)} ThreatDown policies pause endpoint agent updates; component package updates are always automatic")
        else:
            fail_reasons.append(f"{len(paused)} of {len(judged)} ThreatDown policies pause or may pause endpoint agent updates")
            recommendations.append("Turn off 'Pause endpoint agent updates' in: " + "; ".join(paused[:20]))

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
