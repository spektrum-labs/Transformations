"""
Transformation: isEmailSecurityEnabled
Vendor: Abnormal Security  |  Category: Email Security
Evaluates: Validates that the Abnormal email security service is active and returning
threat data, confirming the product is deployed and operational.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for iter_idx in range(3):
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
                "transformationId": "isEmailSecurityEnabled",
                "vendor": "Abnormal Security",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isEmailSecurityEnabled"
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

        email_security_enabled = False
        threat_count = 0

        if isinstance(data, dict):
            threats = data.get("threats", data.get("results", []))
            if isinstance(threats, list):
                # A valid threats list (even empty) confirms the service is active
                email_security_enabled = True
                threat_count = len(threats)
            elif "pageNumber" in data or "nextPageNumber" in data:
                # Paginated response structure confirms the service is active
                email_security_enabled = True

        if email_security_enabled:
            pass_reasons.append("Abnormal Security email protection is active and operational")
            if threat_count > 0:
                pass_reasons.append(str(threat_count) + " threat(s) currently tracked by Abnormal Security")
        else:
            fail_reasons.append("Abnormal Security email security service is not active or not returning data")
            recommendations.append(
                "Verify Abnormal Security is deployed and the API token has the required permissions"
            )

        return create_response(
            result={criteriaKey: email_security_enabled, "threatCount": threat_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"emailSecurityEnabled": email_security_enabled, "threatCount": threat_count}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
