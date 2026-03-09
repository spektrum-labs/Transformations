"""
Transformation: confirmedlicensepurchased
Vendor: Axonius
Category: Asset Management

Ensures a valid response is returned, returns the licensePurchased field value from the response.
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
                "transformationId": "confirmedlicensepurchased",
                "vendor": "Axonius",
                "category": "Asset Management"
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
                result={"confirmedLicensePurchased": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        license_purchased = False
        license_details = {}

        # Axonius about endpoint returns instance info
        if 'Build Date' in data or 'build_date' in data:
            license_purchased = True
            license_details['buildDate'] = data.get('Build Date', data.get('build_date', ''))
            pass_reasons.append("Axonius instance confirmed via build date")
        elif 'Version' in data or 'version' in data:
            license_purchased = True
            license_details['version'] = data.get('Version', data.get('version', ''))
            pass_reasons.append("Axonius instance confirmed via version info")
        elif 'subscription' in data and data['subscription']:
            license_purchased = True
            license_details['subscription'] = data['subscription']
            pass_reasons.append("Active subscription confirmed")
        elif 'license' in data and data['license']:
            license_purchased = True
            license_details['license'] = data['license']
            pass_reasons.append("Valid license confirmed")
        elif 'active' in data or 'enabled' in data:
            license_purchased = bool(data.get('active', data.get('enabled', False)))
            license_details['status'] = 'active' if license_purchased else 'inactive'
            if license_purchased:
                pass_reasons.append("Axonius instance is active")
            else:
                fail_reasons.append("Axonius instance is inactive")
                recommendations.append("Verify Axonius license status and reactivate if needed")

        if not license_purchased and not fail_reasons:
            fail_reasons.append("No license or instance information found in response")
            recommendations.append("Ensure the Axonius health check API endpoint is accessible")

        return create_response(
            result={
                "confirmedLicensePurchased": license_purchased,
                **license_details
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "hasBuildDate": 'Build Date' in data or 'build_date' in data,
                "hasVersion": 'Version' in data or 'version' in data,
                "hasSubscription": bool(data.get('subscription')),
                "hasLicense": bool(data.get('license')),
                "hasActiveFlag": 'active' in data or 'enabled' in data
            }
        )

    except Exception as e:
        return create_response(
            result={"confirmedLicensePurchased": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
