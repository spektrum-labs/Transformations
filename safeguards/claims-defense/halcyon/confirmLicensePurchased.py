"""
Transformation: confirmLicensePurchased
Vendor: Halcyon  |  Category: Claims Defense
Evaluates: Validates that a Halcyon license has been purchased and the account is in an
active (non-suspended, non-expired) state. Uses the getLicenseInfo endpoint which returns
licensePurchased, license, accountName, and status fields.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmLicensePurchased", "vendor": "Halcyon", "category": "Claims Defense"}
        }
    }


def evaluate(data):
    criteriaKey = "confirmLicensePurchased"
    try:
        license_purchased = data.get("licensePurchased", False)
        if license_purchased is None:
            license_purchased = False
        purchased = bool(license_purchased)

        raw_status = data.get("status", "")
        if raw_status is None:
            raw_status = ""
        account_status = str(raw_status).lower().strip()

        account_name = data.get("accountName", "")
        if account_name is None:
            account_name = ""
        account_name = str(account_name)

        license_info = data.get("license", {})
        if license_info is None:
            license_info = {}

        license_type = ""
        license_expiry = ""
        if isinstance(license_info, dict):
            license_type = str(license_info.get("type", "") or "")
            license_expiry = str(license_info.get("expiresAt", "") or license_info.get("expiry", "") or license_info.get("expirationDate", "") or "")

        inactive_statuses = ["inactive", "suspended", "expired", "cancelled", "canceled", "disabled", "terminated"]
        status_ok = account_status not in inactive_statuses

        result_value = purchased and status_ok

        return {
            criteriaKey: result_value,
            "licensePurchased": purchased,
            "accountStatus": account_status,
            "accountName": account_name,
            "licenseType": license_type,
            "licenseExpiry": license_expiry,
            "statusCheckPassed": status_ok
        }
    except Exception as e:
        return {criteriaKey: False, "error": str(e)}


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

        purchased = eval_result.get("licensePurchased", False)
        account_status = eval_result.get("accountStatus", "")
        account_name = eval_result.get("accountName", "")
        status_ok = eval_result.get("statusCheckPassed", True)
        license_type = eval_result.get("licenseType", "")
        license_expiry = eval_result.get("licenseExpiry", "")

        if result_value:
            pass_reasons.append("Halcyon license is confirmed purchased and account is in an active state.")
            if account_name:
                pass_reasons.append("Account: " + account_name)
            if account_status:
                pass_reasons.append("Account status: " + account_status)
            if license_type:
                additional_findings.append("License type: " + license_type)
            if license_expiry:
                additional_findings.append("License expiry: " + license_expiry)
        else:
            if not purchased:
                fail_reasons.append("licensePurchased is false or not set in the Halcyon account response.")
                recommendations.append("Purchase a Halcyon license and ensure it is activated for this tenant.")
            if not status_ok:
                fail_reasons.append("Account status is '" + account_status + "', which indicates the license is not active.")
                recommendations.append("Renew or reactivate the Halcyon license. Contact your Halcyon account representative.")
            if not recommendations:
                recommendations.append("Verify Halcyon license status in the management console under Settings > Account.")

        if "error" in eval_result:
            fail_reasons.append(eval_result["error"])

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {
            "licensePurchased": purchased,
            "accountStatus": account_status,
            "accountName": account_name
        }

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=summary_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
