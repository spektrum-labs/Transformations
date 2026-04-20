"""
Transformation: confirmedLicensePurchased
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether a valid, non-trial, non-expired Rubrik license has been purchased and is active.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Rubrik", "category": "Backup"}
        }
    }


def parse_expiry_date(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        parts = date_str.split("T")[0].split("-")
        if len(parts) == 3:
            return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        pass
    return None


def is_date_in_future(date_tuple):
    if date_tuple is None:
        return True
    now = datetime.utcnow()
    y, m, d = date_tuple
    if y > now.year:
        return True
    if y == now.year and m > now.month:
        return True
    if y == now.year and m == now.month and d >= now.day:
        return True
    return False


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"confirmedLicensePurchased": False, "error": "Unexpected response format"}

        license_status = data.get("licenseStatus", data.get("status", data.get("licenseState", "")))
        is_trial = data.get("isTrial", data.get("trial", False))
        has_expired = data.get("hasExpired", data.get("expired", False))
        expiration_date = data.get("expirationDate", data.get("expiry", data.get("licenseExpiry", None)))
        edition = data.get("edition", data.get("licenseEdition", ""))

        status_str = str(license_status).upper() if license_status else ""
        valid_statuses = ["VALID", "ACTIVE", "PURCHASED", "LICENSED", "SUCCESS"]
        invalid_statuses = ["EXPIRED", "INVALID", "SUSPENDED", "REVOKED", "TRIAL"]

        status_valid = any(s in status_str for s in valid_statuses)
        status_invalid = any(s in status_str for s in invalid_statuses)

        not_trial = not bool(is_trial)
        not_expired = not bool(has_expired)

        expiry_tuple = parse_expiry_date(expiration_date)
        expiry_in_future = is_date_in_future(expiry_tuple)

        if not status_str:
            license_confirmed = not_trial and not_expired and expiry_in_future
        else:
            license_confirmed = status_valid and not status_invalid and not_trial and not_expired and expiry_in_future

        expiry_display = expiration_date if expiration_date else "Not specified"

        return {
            "confirmedLicensePurchased": license_confirmed,
            "licenseStatus": str(license_status) if license_status else "Unknown",
            "isTrial": bool(is_trial),
            "hasExpired": bool(has_expired),
            "licenseExpiry": expiry_display,
            "licenseEdition": str(edition) if edition else "Unknown"
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Rubrik license is confirmed as purchased and active")
            additional_findings.append("License status: " + str(extra_fields.get("licenseStatus", "Unknown")))
            additional_findings.append("License edition: " + str(extra_fields.get("licenseEdition", "Unknown")))
            additional_findings.append("Expiry: " + str(extra_fields.get("licenseExpiry", "Not specified")))
        else:
            fail_reasons.append("Rubrik license is not confirmed as a valid purchased license")
            if extra_fields.get("isTrial"):
                fail_reasons.append("License is flagged as a trial")
                recommendations.append("Purchase a full Rubrik license to replace the trial")
            if extra_fields.get("hasExpired"):
                fail_reasons.append("License has expired")
                recommendations.append("Renew the Rubrik license immediately")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not recommendations:
                recommendations.append("Verify license status in the Rubrik cluster management console")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"licenseStatus": extra_fields.get("licenseStatus", "Unknown"), "isTrial": extra_fields.get("isTrial", False)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
