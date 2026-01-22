"""
Transformation: compliancepercentage
Vendor: Cloud Security
Category: Cloud Security / Compliance

Evaluates the compliance percentage of Cloud Security Compliance findings.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "compliancepercentage",
                "vendor": "Cloud Security",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"compliancePercentage": 0, "CIScompliancePercentage": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Handle Findings array
        findings = []
        if isinstance(data, dict) and 'Findings' in data:
            findings = data['Findings']
        elif isinstance(data, list):
            findings = data

        passed = [obj for obj in findings if 'Compliance' in obj and 'Status' in obj['Compliance'] and str(obj['Compliance']['Status']).lower() == "passed"]
        failed = [obj for obj in findings if 'Compliance' in obj and 'Status' in obj['Compliance'] and str(obj['Compliance']['Status']).lower() == "failed"]

        total = len(passed) + len(failed)
        compliance_percentage = int((len(passed) / total) * 100) if total > 0 else 0

        if compliance_percentage >= 80:
            pass_reasons.append(f"Good compliance level: {compliance_percentage}% ({len(passed)} passed, {len(failed)} failed)")
        elif compliance_percentage >= 50:
            fail_reasons.append(f"Moderate compliance level: {compliance_percentage}%")
            recommendations.append("Address failed compliance findings to improve security posture")
        else:
            fail_reasons.append(f"Low compliance level: {compliance_percentage}%")
            recommendations.append("Urgently address compliance failures to meet security requirements")

        return create_response(
            result={
                "compliancePercentage": compliance_percentage,
                "CIScompliancePercentage": compliance_percentage,
                "totalPassed": len(passed),
                "totalFailed": len(failed),
                "totalFindings": total
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "compliancePercentage": compliance_percentage,
                "totalPassed": len(passed),
                "totalFailed": len(failed),
                "totalFindings": total
            }
        )

    except Exception as e:
        return create_response(
            result={"compliancePercentage": 0, "CIScompliancePercentage": 0},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
