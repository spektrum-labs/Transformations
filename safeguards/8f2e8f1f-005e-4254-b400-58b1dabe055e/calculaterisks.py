"""
Transformation: calculaterisks
Vendor: Security Ratings
Category: Risk Management

Calculates the risk score based on the input data.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "calculaterisks",
                "vendor": "Security Ratings",
                "category": "Risk Management"
            }
        }
    }


def transform(input):
    low_ratings = []
    lowest_rating = 0
    low_count = 0

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"riskThreshold": 0, "count": 0, "lowratings": []},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        rating_details = data.get("rating_details", {}) if isinstance(data, dict) else {}

        for attribute in rating_details:
            try:
                current_rating = int(rating_details[attribute].get('rating', 0))
            except:
                current_rating = 0
            if current_rating < 700:
                low_ratings.append(rating_details[attribute])
                if current_rating < lowest_rating or lowest_rating == 0:
                    lowest_rating = current_rating
                low_count += 1

        if low_count == 0:
            pass_reasons.append("All security ratings are above threshold (700)")
        else:
            fail_reasons.append(f"{low_count} attributes have ratings below threshold")
            recommendations.append("Review and address security issues for attributes with low ratings")

        return create_response(
            result={
                "riskThreshold": lowest_rating,
                "count": low_count,
                "lowratings": low_ratings
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "lowestRating": lowest_rating,
                "lowRatingCount": low_count,
                "totalAttributes": len(rating_details)
            }
        )

    except Exception as e:
        return create_response(
            result={"riskThreshold": 0, "count": 0, "lowratings": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
