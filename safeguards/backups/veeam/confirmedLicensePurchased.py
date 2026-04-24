"""
Transformation: confirmedLicensePurchased
Vendor: Veeam  |  Category: Backup
Evaluates: Whether a valid, non-expired, purchased Veeam Backup & Replication license
           is installed based on GET /api/v1/license response.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Veeam", "category": "Backup"}
        }
    }


def parse_date_str(date_str):
    if not date_str:
        return None
    try:
        cleaned = date_str.replace("Z", "").replace("T", " ")
        parts = cleaned.split(" ")
        date_parts = parts[0].split("-")
        if len(date_parts) >= 3:
            year = int(date_parts[0])
            month = int(date_parts[1])
            day = int(date_parts[2])
            return datetime(year, month, day)
    except Exception:
        return None
    return None


def evaluate(data):
    try:
        status = data.get("status", "")
        license_type = data.get("licenseType", "")
        expiration_date_str = data.get("expirationDate", "")
        edition = data.get("edition", "")
        support_id = data.get("supportId", "")
        total_protected_vms = data.get("totalProtectedVms", 0)
        non_purchased_types = ["Evaluation", "Community", "NFR"]
        status_upper = status.upper() if status else ""
        is_status_valid = status_upper in ["VALID", "WARNING"]
        is_purchased_type = license_type not in non_purchased_types
        is_not_expired = True
        expiration_note = "No expiration date provided"
        if expiration_date_str:
            exp_date = parse_date_str(expiration_date_str)
            if exp_date is not None:
                now = datetime.utcnow()
                is_not_expired = exp_date >= now
                expiration_note = "Expires: " + expiration_date_str
            else:
                expiration_note = "Could not parse expiration date: " + expiration_date_str
        confirmed = is_status_valid and is_purchased_type and is_not_expired
        return {
            "confirmedLicensePurchased": confirmed,
            "licenseStatus": status,
            "licenseType": license_type,
            "licenseEdition": edition,
            "expirationDate": expiration_date_str,
            "totalProtectedVms": total_protected_vms,
            "isStatusValid": is_status_valid,
            "isPurchasedType": is_purchased_type,
            "isNotExpired": is_not_expired,
            "expirationNote": expiration_note
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
        license_status = eval_result.get("licenseStatus", "")
        license_type = eval_result.get("licenseType", "")
        license_edition = eval_result.get("licenseEdition", "")
        expiration_date = eval_result.get("expirationDate", "")
        total_protected_vms = eval_result.get("totalProtectedVms", 0)
        is_status_valid = eval_result.get("isStatusValid", False)
        is_purchased_type = eval_result.get("isPurchasedType", False)
        is_not_expired = eval_result.get("isNotExpired", False)
        expiration_note = eval_result.get("expirationNote", "")
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("License status is valid: " + license_status)
            pass_reasons.append("License type confirms a purchased license: " + license_type)
            pass_reasons.append(expiration_note)
            additional_findings.append("Edition: " + license_edition)
            additional_findings.append("Total protected VMs: " + str(total_protected_vms))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                if not is_status_valid:
                    fail_reasons.append("License status is not valid: '" + license_status + "' (expected Valid or Warning)")
                    recommendations.append("Resolve the license status issue in Veeam Backup and Replication")
                if not is_purchased_type:
                    fail_reasons.append("License type '" + license_type + "' is not a purchased license")
                    recommendations.append("Purchase a Veeam license (Perpetual or Subscription) to replace Evaluation/Community/NFR")
                if not is_not_expired:
                    fail_reasons.append("License has expired on: " + expiration_date)
                    recommendations.append("Renew the Veeam license before the expiration date")
        return create_response(
            result={criteriaKey: result_value, "licenseStatus": license_status, "licenseType": license_type, "licenseEdition": license_edition, "expirationDate": expiration_date, "totalProtectedVms": total_protected_vms},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"licenseStatus": license_status, "licenseType": license_type, "expirationDate": expiration_date})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
