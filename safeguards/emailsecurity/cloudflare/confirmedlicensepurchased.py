"""
Transformation: confirmedLicensePurchased
Vendor: Cloudflare Email Security (formerly Area 1)
Category: Email Security / Licensing

Evaluates if a valid Cloudflare Email Security subscription is active.
Checks the token verification response for active status and valid token ID.
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Cloudflare Email Security",
                "category": "Email Security"
            }
        }
    }


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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        license_purchased = False
        license_details = {}

        if isinstance(data, dict):
            # Cloudflare token verify response: {"id": "...", "status": "active"}
            status = data.get('status', '')
            if isinstance(status, str) and status.lower() == 'active':
                license_purchased = True
                license_details['status'] = status
                if 'id' in data:
                    license_details['tokenId'] = data['id']

            # Check for success flag in Cloudflare envelope
            elif data.get('success') is True:
                license_purchased = True
                license_details['status'] = 'active'
                result_data = data.get('result', {})
                if isinstance(result_data, dict):
                    if 'status' in result_data:
                        license_details['status'] = result_data['status']
                    if 'id' in result_data:
                        license_details['tokenId'] = result_data['id']

            # Fallback checks
            elif 'subscription' in data and data['subscription']:
                license_purchased = True
                license_details['subscription'] = data['subscription']
            elif 'active' in data or 'enabled' in data:
                license_purchased = bool(data.get('active', data.get('enabled', False)))
                license_details['status'] = 'active' if license_purchased else 'inactive'

        if license_purchased:
            pass_reasons.append("Cloudflare Email Security license active and confirmed")
        else:
            fail_reasons.append("Cloudflare Email Security license has not been purchased or confirmed")
            recommendations.append("Ensure valid Cloudflare Email Security subscription is active")

        return create_response(
            result={criteriaKey: license_purchased, **license_details},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"licensePurchased": license_purchased, **license_details}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
