"""
Transformation: isDNSSECEnabled
Vendor: Cloudflare
Category: Cloud Security / DNSSEC

Checks if DNSSEC is enabled in Cloudflare.
Validates DNSSEC status, algorithm, and DS record presence.
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
                "transformationId": "isDNSSECEnabled",
                "vendor": "Cloudflare",
                "category": "Cloud Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isDNSSECEnabled"

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
        additional_findings = []

        dnssec_enabled = False
        dnssec_details = {}

        if isinstance(data, dict):
            status = str(data.get('status', '')).lower()
            if status == 'active':
                dnssec_enabled = True
            dnssec_details['status'] = data.get('status', '')

            # Additional DNSSEC fields
            algorithm = data.get('algorithm', '')
            if algorithm:
                dnssec_details['algorithm'] = algorithm

            ds = data.get('ds', '')
            if ds:
                dnssec_details['hasDS'] = True
                additional_findings.append("DS record is configured")

        if dnssec_enabled:
            reason = "DNSSEC is enabled and active"
            if dnssec_details.get('algorithm'):
                reason += f" (algorithm: {dnssec_details['algorithm']})"
            pass_reasons.append(reason)
        else:
            fail_reasons.append(f"DNSSEC is not enabled (status: {dnssec_details.get('status', 'unknown')})")
            recommendations.append("Enable DNSSEC in Cloudflare to protect against DNS spoofing")

        return create_response(
            result={criteriaKey: dnssec_enabled, **dnssec_details},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"dnssecEnabled": dnssec_enabled, **dnssec_details}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
