"""
Transformation: isOfacScreeningClear
Vendor: OFAC (self-hosted sanctions screening service)
Category: Compliance

Evaluates the response from the OFAC screening service's POST /screen endpoint and
returns whether the screened entity is clear of sanctions matches.

Fails closed: this transformation returns ``isOfacScreeningClear = False`` unless
the screening response explicitly reports a clean clear. Any error, an "Unknown"
status, or a surfaced ``potential_match`` (which requires human adjudication and is
never an auto-confirmed hit) all resolve to False.

Runs in the RestrictedPython sandbox — only ``json`` and ``datetime`` are imported;
all cryptographic receipt hashing happens in the screening service, not here.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isOfacScreeningClear"

    def parse_input(input_data):
        if isinstance(input_data, str):
            return json.loads(input_data)
        if isinstance(input_data, bytes):
            return json.loads(input_data.decode("utf-8"))
        if isinstance(input_data, dict):
            return input_data
        raise ValueError("Input must be JSON string, bytes, or dict")

    def unwrap(data):
        wrapper_keys = ["data", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            if isinstance(data, dict):
                for key in wrapper_keys:
                    if key in data and isinstance(data.get(key), dict):
                        data = data[key]
                        unwrapped = True
                        break
            if not unwrapped:
                break
        return data

    def create_response(result, pass_reasons=None, fail_reasons=None,
                        recommendations=None, input_summary=None,
                        transformation_errors=None, api_errors=None):
        return {
            "transformedResponse": result,
            "additionalInfo": {
                "dataCollection": {
                    "status": "error" if (api_errors or []) else "success",
                    "errors": api_errors or [],
                },
                "transformation": {
                    "status": "error" if (transformation_errors or []) else "success",
                    "errors": transformation_errors or [],
                    "inputSummary": input_summary or {},
                },
                "evaluation": {
                    "passReasons": pass_reasons or [],
                    "failReasons": fail_reasons or [],
                    "recommendations": recommendations or [],
                },
                "metadata": {
                    "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                    "schemaVersion": "1.0",
                    "transformationId": "isOfacScreeningClear",
                    "vendor": "OFAC",
                    "category": "Compliance",
                },
            },
        }

    try:
        data = unwrap(parse_input(input))

        if not isinstance(data, dict):
            return create_response(
                result={criteriaKey: False},
                fail_reasons=["Screening response was not an object; failing closed"],
                transformation_errors=["unexpected response shape"],
            )

        # Derive status. Prefer the explicit status field; fall back to is_clear.
        status = data.get("status")
        if status is None:
            if isinstance(data.get("is_clear"), bool):
                status = "clear" if data.get("is_clear") else "potential_match"
            else:
                status = "unknown"
        status = str(status).lower()

        potential_matches = data.get("potential_matches") or []
        match_count = len(potential_matches) if isinstance(potential_matches, list) else 0

        # Clear only when the service says so AND there are no surfaced matches.
        is_clear = status == "clear" and match_count == 0

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if is_clear:
            pass_reasons.append("OFAC screening returned a clean clear with no potential matches")
        elif status == "potential_match" or match_count > 0:
            fail_reasons.append(
                str(match_count) + " potential OFAC match(es) surfaced; requires human adjudication"
            )
            recommendations.append("Adjudicate the surfaced potential matches before proceeding")
        else:
            fail_reasons.append("OFAC screening status '" + status + "' is not a clean clear; failing closed")
            recommendations.append("Re-run screening once the OFAC service reports a definitive result")

        return create_response(
            result={criteriaKey: is_clear},
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"status": status, "potentialMatchCount": match_count},
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error; failing closed: " + str(e)],
        )
