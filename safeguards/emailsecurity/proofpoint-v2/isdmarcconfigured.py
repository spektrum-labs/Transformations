"""
Transformation: isDMARCConfigured
Vendor: Proofpoint  |  Category: Email Security
Evaluates: whether the domain publishes a DMARC record.

The Proofpoint Essentials features body (getFeatures) has no DMARC setting. Its anti_spoofing flag
is a different control (sender-spoofing protection inside Proofpoint), so it is not read here: an
enabled anti_spoofing flag does not prove a DMARC record exists and a disabled one does not prove
it is missing. DMARC is answered only from a DNS lookup answer under a DMARC key: the record text
(starts with v=DMARC1) is True, a stated absent record (False) is False. A body with no such answer,
which is every getFeatures body, is None (Not evaluated) together with a dataCollection error.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDMARCConfigured", "vendor": "Proofpoint", "category": "Email Security"}
        }
    }


RECORD_PREFIX = "v=dmarc1"


def read_dmarc_answer(data):
    """The DNS lookup's DMARC answer: True for the record text, False for a stated absent record, None otherwise.

    None means the body carries no usable DMARC answer: no DMARC key, an error word, a blank value, the
    record of another protocol, a number, a list or an object. It is never a record found or absent."""
    if not isinstance(data, dict):
        return None
    value = None
    if "DMARC" in data:
        value = data.get("DMARC")
    else:
        for key, candidate in data.items():
            if isinstance(key, str) and key.lower() == "dmarc":
                value = candidate
                break
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low == "false":
            return False
        if low.startswith(RECORD_PREFIX):
            return True
    return None


def not_evaluated(validation, reason, transformation_errors=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={"isDMARCConfigured": None},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[reason],
        recommendations=["Read DMARC from the domain's DNS record; the Proofpoint features API does not report it"]
    )


def transform(input):
    criteriaKey = "isDMARCConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(validation, "Could not read the response: input validation failed")

        answer = read_dmarc_answer(data)
        if answer is None:
            return not_evaluated(
                validation,
                "The response carries no DMARC answer: the Proofpoint features API does not report DMARC, "
                "so it needs a DNS lookup of the domain's DMARC record")

        if answer:
            pass_reasons = ["A DMARC record is published for the domain"]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = ["No DMARC record is published for the domain"]
            recommendations = ["Publish a DMARC record for the domain"]

        return create_response(
            result={criteriaKey: answer},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: answer}
        )

    except Exception as e:
        # An error is Not evaluated, never a fail: None plus a dataCollection error.
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            f"Transformation error: {str(e)}",
            transformation_errors=[str(e)])
