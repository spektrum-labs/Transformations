"""
Transformation: confirmLicensePurchased
Vendor: Halcyon  |  Category: epp
Evaluates: Ensures a valid license response is returned and the licensePurchased field is truthy,
confirming an active Halcyon subscription.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmLicensePurchased", "vendor": "Halcyon", "category": "epp"}
        }
    }


def parse_expiry_date(expiry_str):
    if not expiry_str or not isinstance(expiry_str, str):
        return None
    try:
        parts = expiry_str[:10].split("-")
        if len(parts) == 3:
            year = int(parts[0])
            month = int(parts[1])
            day = int(parts[2])
            return datetime(year, month, day)
    except Exception:
        pass
    try:
        parts = expiry_str[:10].split("/")
        if len(parts) == 3:
            month = int(parts[0])
            day = int(parts[1])
            year = int(parts[2])
            return datetime(year, month, day)
    except Exception:
        pass
    return None


def evaluate(data):
    try:
        license_data = data.get("data", data)
        if not isinstance(license_data, dict):
            return {
                "confirmLicensePurchased": False,
                "licensePurchased": False,
                "error": "License data is not a valid object"
            }

        if len(license_data) == 0:
            return {
                "confirmLicensePurchased": False,
                "licensePurchased": False,
                "error": "Empty license response returned from API"
            }

        license_purchased = license_data.get("licensePurchased", None)
        if license_purchased is None:
            license_purchased = license_data.get("license_purchased", None)
        if license_purchased is None:
            license_purchased = license_data.get("purchased", None)
        if license_purchased is None:
            license_purchased = license_data.get("active", None)

        purchased_bool = False
        if license_purchased is True:
            purchased_bool = True
        elif isinstance(license_purchased, str) and license_purchased.lower() in ["true", "yes", "active", "1"]:
            purchased_bool = True
        elif isinstance(license_purchased, int) and license_purchased == 1:
            purchased_bool = True

        if license_purchased is None:
            status_val = license_data.get("status", "") or license_data.get("licenseStatus", "") or license_data.get("license_status", "")
            if isinstance(status_val, str) and status_val.lower() in ["active", "valid", "purchased", "enabled"]:
                purchased_bool = True

        license_status = license_data.get("status", "") or license_data.get("licenseStatus", "")
        expiry_date_raw = license_data.get("expiryDate", "") or license_data.get("expiry_date", "") or license_data.get("expiry", "") or license_data.get("validUntil", "") or license_data.get("valid_until", "")
        licensed_seats = license_data.get("seats", None) or license_data.get("licensedSeats", None) or license_data.get("licensed_seats", None)
        license_type = license_data.get("type", "") or license_data.get("licenseType", "") or license_data.get("license_type", "")

        expiry_warning = None
        if expiry_date_raw:
            expiry_dt = parse_expiry_date(str(expiry_date_raw))
            if expiry_dt is not None:
                now = datetime.utcnow()
                days_remaining = (expiry_dt - now).days
                if days_remaining < 0:
                    purchased_bool = False
                    expiry_warning = "License has expired (expiry: " + str(expiry_date_raw) + ")"
                elif days_remaining < 30:
                    expiry_warning = "License expires in " + str(days_remaining) + " days (expiry: " + str(expiry_date_raw) + ")"

        result = {
            "confirmLicensePurchased": purchased_bool,
            "licensePurchased": purchased_bool
        }
        if license_status:
            result["licenseStatus"] = str(license_status)
        if expiry_date_raw:
            result["expiryDate"] = str(expiry_date_raw)
        if licensed_seats is not None:
            result["licensedSeats"] = licensed_seats
        if license_type:
            result["licenseType"] = str(license_type)
        if expiry_warning:
            result["expiryWarning"] = expiry_warning
        return result
    except Exception as e:
        return {"confirmLicensePurchased": False, "licensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        license_status = eval_result.get("licenseStatus", "")
        expiry_date = eval_result.get("expiryDate", "")
        licensed_seats = eval_result.get("licensedSeats", None)
        license_type = eval_result.get("licenseType", "")
        expiry_warning = eval_result.get("expiryWarning", "")
        if result_value:
            pass_reasons.append("A valid Halcyon license has been purchased and is active")
            if license_status:
                pass_reasons.append("License status: " + str(license_status))
            if expiry_date:
                pass_reasons.append("License expiry: " + str(expiry_date))
            if licensed_seats is not None:
                pass_reasons.append("Licensed seats: " + str(licensed_seats))
            if license_type:
                pass_reasons.append("License type: " + str(license_type))
            if expiry_warning:
                additional_findings.append(expiry_warning)
        else:
            fail_reasons.append("No valid active Halcyon license confirmed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if expiry_warning:
                fail_reasons.append(expiry_warning)
            if license_status:
                additional_findings.append("Reported license status: " + str(license_status))
            recommendations.append("Ensure a valid Halcyon subscription license has been purchased and is currently active")
            recommendations.append("Contact Halcyon support or your account representative to resolve any licensing issues")
            if expiry_warning:
                recommendations.append("Renew the Halcyon license before it expires to avoid loss of protection coverage")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"licensePurchased": eval_result.get("licensePurchased", False), "licenseStatus": license_status, "expiryDate": expiry_date}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
