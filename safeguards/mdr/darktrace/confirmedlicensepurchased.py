"""
Transformation: confirmedLicensePurchased
Vendor: Darktrace  |  Category: Managed Detection & Response
Evaluates: Active Darktrace license by verifying instance status and connectivity
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Darktrace", "category": "Managed Detection & Response"}
        }
    }


def parse_api_error(data):
    if isinstance(data, dict):
        for key in ["error", "message", "detail", "errors"]:
            if key in data:
                val = data[key]
                if isinstance(val, str):
                    return val
                if isinstance(val, list) and len(val) > 0:
                    return str(val[0])
    return None


def evaluate(data):
    """Core evaluation logic for Darktrace license verification.

    Checks for indicators that the Darktrace instance is licensed and operational:
    - HTTP status codes indicating a valid, reachable instance
    - License or status fields in the response
    - Active/enabled flags
    - Version info (presence implies a licensed instance)
    """
    try:
        license_purchased = False
        extra = {}

        api_error = parse_api_error(data)
        if api_error:
            return {"confirmedLicensePurchased": False, "error": api_error}

        status = data.get("status", "")
        if isinstance(status, str):
            status_lower = status.lower()
        else:
            status_lower = ""

        if status_lower in ("active", "ok", "healthy", "running", "operational"):
            license_purchased = True
            extra["status"] = status

        if "license" in data and data["license"]:
            license_info = data["license"]
            if isinstance(license_info, dict):
                lic_status = license_info.get("status", "")
                if isinstance(lic_status, str) and lic_status.lower() in ("active", "valid", "ok"):
                    license_purchased = True
                expiry = license_info.get("expiry", license_info.get("expiryDate", ""))
                if expiry:
                    extra["licenseExpiry"] = str(expiry)
            elif isinstance(license_info, bool):
                license_purchased = license_info
            elif isinstance(license_info, str) and license_info.lower() in ("active", "valid"):
                license_purchased = True

        if "licensed" in data:
            val = data["licensed"]
            if isinstance(val, bool):
                license_purchased = val
            elif isinstance(val, str):
                license_purchased = val.lower() in ("true", "yes", "1")

        if "active" in data or "enabled" in data:
            active_val = data.get("active", data.get("enabled", False))
            if isinstance(active_val, bool):
                license_purchased = license_purchased or active_val
            elif isinstance(active_val, str):
                license_purchased = license_purchased or active_val.lower() in ("true", "yes", "1")

        if "version" in data and data["version"] and not license_purchased:
            license_purchased = True
            extra["version"] = str(data["version"])

        return {"confirmedLicensePurchased": license_purchased, **extra}

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
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify Darktrace instance is licensed and accessible")
            recommendations.append("Check that the API Auth Token has sufficient permissions")

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
