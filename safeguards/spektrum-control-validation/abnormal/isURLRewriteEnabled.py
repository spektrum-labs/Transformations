"""
Transformation: isURLRewriteEnabled
Vendor: Abnormal Security
Category: Email Security / URL Protection

Checks if URL analysis and protection is active in Abnormal Security.
Abnormal does not expose URL rewriting settings via API, so this evaluates whether
the threat detection platform (which includes URL analysis) is active by confirming
a successful /v1/threats response.
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
                "transformationId": "isURLRewriteEnabled",
                "vendor": "Abnormal Security",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isURLRewriteEnabled"

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

        url_protection_active = False
        threat_count = 0

        if isinstance(data, dict):
            # A successful /v1/threats response with a "threats" array confirms
            # Abnormal's threat detection platform is active, which includes
            # URL analysis and rewriting as a core capability.
            threats = data.get('threats', [])
            if isinstance(threats, list):
                url_protection_active = True
                threat_count = len(threats)

        if url_protection_active:
            pass_reasons.append(
                "Abnormal Security URL analysis and protection is active"
                " (" + str(threat_count) + " threats currently tracked)"
            )
        else:
            fail_reasons.append("Unable to confirm Abnormal Security URL protection is active")
            recommendations.append("Verify Abnormal Security integration is properly configured and the API token has read access")

        return create_response(
            result={
                criteriaKey: url_protection_active,
                "threatCount": threat_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "urlProtectionActive": url_protection_active,
                "threatCount": threat_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
