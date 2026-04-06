"""
Transformation: confirmedLicensePurchased
Vendor: Kaseya
Category: Endpoint Protection

Evaluates confirmedLicensePurchased for Kaseya
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Kaseya", "category": "Endpoint Protection"}
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

        data = data.get("apiResponse", data)
        data = data.get("Data", data)

        # Check for explicit license purchased field
        if "licensePurchased" in data:
            return create_response(
                result={"confirmedLicensePurchased": bool(data["licensePurchased"])},
                validation=validation
            )
        # Check for license status indicators
        license_status = data.get("licenseStatus", data.get("status", "")).lower()
        if license_status in ["active", "valid", "licensed", "enabled"]:
            return create_response(
                result={"confirmedLicensePurchased": True},
                validation=validation
            )
        # Check for environment ID and version as indicators of valid license
        environment_id = data.get("id", data.get("environmentId", ""))
        version = data.get("version", "")
        environment_name = data.get("name", data.get("environmentName", ""))

        if environment_id and version:
            return create_response(
                result={"confirmedLicensePurchased": True},
                validation=validation
            )
        # Check for license type presence
        license_type = data.get("licenseType", data.get("type", ""))
        if license_type:
            return create_response(
                result={"confirmedLicensePurchased": True},
                validation=validation
            )
        # Check for expiration date (presence indicates license exists)
        expiration = data.get("expirationDate", data.get("licenseExpiration", ""))
        if expiration:
            return create_response(
                result={"confirmedLicensePurchased": True},
                validation=validation
            )
        # Check for licensed features or modules
        features = data.get("features", data.get("licensedFeatures", data.get("modules", [])))
        if features and len(features) > 0:
            return create_response(
                result={"confirmedLicensePurchased": True},
                validation=validation
            )
        # Default to False if no license indicators found
        return create_response(
            result={"confirmedLicensePurchased": False},
            validation=validation,
            fail_reasons=["confirmedLicensePurchased check failed"]
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
