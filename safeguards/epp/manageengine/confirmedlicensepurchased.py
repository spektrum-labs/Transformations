"""
Transformation: confirmedLicensePurchased
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: Whether the Endpoint Central server is active with a valid license.
Source: GET /api/1.4/desktop/serverproperties
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if ManageEngine Endpoint Central server is active with a valid license."""
    try:
        # serverproperties returns server info including product name, version, build, license type
        server_name = data.get("server_name", data.get("serverName", data.get("name", "")))
        product = data.get("product_name", data.get("productName", data.get("product", "")))
        version = data.get("product_version", data.get("productVersion", data.get("version", "")))
        build_number = data.get("build_number", data.get("buildNumber", data.get("build", "")))
        license_type = data.get("license_type", data.get("licenseType", data.get("license", "")))
        license_expiry = data.get("license_expiry", data.get("licenseExpiry", data.get("expiry_date", "")))

        # A successful response from serverproperties means the server is active
        is_active = bool(product or server_name or version)

        # Check license type - professional/enterprise/UEM are valid, trial/free may not be
        if license_type:
            license_lower = str(license_type).lower()
            if license_lower in ("expired", "invalid"):
                is_active = False

        return {
            "confirmedLicensePurchased": is_active,
            "serverName": str(server_name),
            "product": str(product),
            "version": str(version),
            "buildNumber": str(build_number),
            "licenseType": str(license_type)
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
            pass_reasons.append("ManageEngine Endpoint Central server is active")
            if extra_fields.get("product"):
                pass_reasons.append(f"Product: {extra_fields['product']}")
            if extra_fields.get("version"):
                pass_reasons.append(f"Version: {extra_fields['version']}")
            if extra_fields.get("licenseType"):
                pass_reasons.append(f"License: {extra_fields['licenseType']}")
        else:
            fail_reasons.append("ManageEngine Endpoint Central server is not responding or license is invalid")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify Endpoint Central server status and license validity in the admin console")

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
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
