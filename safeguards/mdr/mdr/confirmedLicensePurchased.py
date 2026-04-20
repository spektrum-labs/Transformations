"""
Transformation: confirmedLicensePurchased
Vendor: MDR (Sophos)  |  Category: MDR
Evaluates: Whether an active Sophos MDR license is present in the tenant's license list.
Checks for a license item with product type containing 'MDR', a valid active/valid status,
and a non-expired expiry date.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "MDR", "category": "MDR"}
        }
    }


def parse_date_parts(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    cleaned = date_str.split("T")[0]
    parts = cleaned.split("-")
    if len(parts) == 3:
        try:
            year = int(parts[0])
            month = int(parts[1])
            day = int(parts[2])
            return (year, month, day)
        except Exception:
            return None
    return None


def is_date_expired(date_str):
    parts = parse_date_parts(date_str)
    if parts is None:
        return False
    now = datetime.utcnow()
    exp_year = parts[0]
    exp_month = parts[1]
    exp_day = parts[2]
    if exp_year < now.year:
        return True
    if exp_year == now.year and exp_month < now.month:
        return True
    if exp_year == now.year and exp_month == now.month and exp_day < now.day:
        return True
    return False


def is_mdr_license(license_item):
    product_type = license_item.get("productType", "")
    if not isinstance(product_type, str):
        product_type = str(product_type)
    if "mdr" in product_type.lower():
        return True
    product_name = license_item.get("productName", "")
    if not isinstance(product_name, str):
        product_name = str(product_name)
    if "mdr" in product_name.lower():
        return True
    license_type = license_item.get("licenseType", "")
    if not isinstance(license_type, str):
        license_type = str(license_type)
    if "mdr" in license_type.lower():
        return True
    return False


def is_license_active(license_item):
    status = license_item.get("status", "")
    if not isinstance(status, str):
        status = str(status)
    active_statuses = ["active", "valid", "enabled", "current"]
    status_lower = status.lower()
    for s in active_statuses:
        if status_lower == s:
            return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []
        total_licenses = len(items)
        mdr_licenses = [lic for lic in items if is_mdr_license(lic)]
        active_mdr_licenses = [lic for lic in mdr_licenses if is_license_active(lic)]
        valid_mdr_licenses = []
        for lic in active_mdr_licenses:
            expiry = lic.get("expiresAt", lic.get("expiry", lic.get("expiryDate", "")))
            if not is_date_expired(expiry):
                valid_mdr_licenses.append(lic)
        confirmed = len(valid_mdr_licenses) > 0
        found_license_info = ""
        if valid_mdr_licenses:
            first = valid_mdr_licenses[0]
            found_license_info = first.get("productType", first.get("productName", "MDR"))
        return {
            "confirmedLicensePurchased": confirmed,
            "totalLicenses": total_licenses,
            "mdrLicensesFound": len(mdr_licenses),
            "activeMDRLicenses": len(active_mdr_licenses),
            "validNonExpiredMDRLicenses": len(valid_mdr_licenses),
            "licenseProductType": found_license_info
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
        total = extra_fields.get("totalLicenses", 0)
        mdr_found = extra_fields.get("mdrLicensesFound", 0)
        active_mdr = extra_fields.get("activeMDRLicenses", 0)
        valid_mdr = extra_fields.get("validNonExpiredMDRLicenses", 0)
        product_type = extra_fields.get("licenseProductType", "")
        additional_findings.append("Total licenses in tenant: " + str(total))
        additional_findings.append("MDR licenses found: " + str(mdr_found))
        additional_findings.append("Active MDR licenses: " + str(active_mdr))
        additional_findings.append("Valid non-expired MDR licenses: " + str(valid_mdr))
        if result_value:
            pass_reasons.append("A valid, active, non-expired Sophos MDR license is confirmed for this tenant.")
            if product_type:
                pass_reasons.append("License product type: " + product_type)
        else:
            if mdr_found == 0:
                fail_reasons.append("No MDR license was found in the tenant's license list.")
                recommendations.append("Purchase a Sophos MDR license and ensure it is activated in Sophos Central.")
            elif active_mdr == 0:
                fail_reasons.append("MDR license(s) found but none have an active/valid status.")
                recommendations.append("Activate the Sophos MDR license in Sophos Central under My Products > MDR.")
            elif valid_mdr == 0:
                fail_reasons.append("MDR license(s) found but all are expired.")
                recommendations.append("Renew the expired Sophos MDR license to restore coverage.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalLicenses": total, "mdrLicensesFound": mdr_found, "validNonExpiredMDRLicenses": valid_mdr},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
