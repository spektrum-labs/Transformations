"""
Transformation: confirmedLicensePurchased
Vendor: ZenGRC  |  Category: GRC
Evaluates: Whether the ZenGRC instance is accessible and returns valid data from the people endpoint, confirming an active subscription.
Source: GET /api/v2/people
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "ZenGRC", "category": "GRC"}
        }
    }


def evaluate(data):
    """Check if ZenGRC returns valid people data, confirming an active subscription."""
    try:
        # ZenGRC API v2 returns JSON:API format with "data" array
        people = data.get("data", data.get("people", data.get("results", [])))
        if not isinstance(people, list):
            people = [people] if people else []

        total = len(people)

        # Check pagination meta for total count
        meta = data.get("meta", {})
        if isinstance(meta, dict):
            total_records = meta.get("total", meta.get("totalCount", meta.get("total_count", total)))
        else:
            total_records = total

        # A valid response with people data confirms active subscription
        is_active = total > 0 or int(str(total_records)) > 0

        return {
            "confirmedLicensePurchased": is_active,
            "peopleReturned": total,
            "totalPeople": int(str(total_records))
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("ZenGRC instance is active and returning people data")
            if extra_fields.get("totalPeople"):
                pass_reasons.append("Total people in instance: " + str(extra_fields["totalPeople"]))
        else:
            fail_reasons.append("ZenGRC instance returned no people data, subscription may be inactive")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify ZenGRC subscription status and API credentials")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
