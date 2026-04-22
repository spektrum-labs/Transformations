"""
Transformation: isEmailSecurityEnabled
Vendor: Mimecast  |  Category: emailsecurity
Evaluates: Confirms that the Mimecast Email Security service is active and the account
is correctly provisioned for email security processing by inspecting account settings
and package entitlements returned from the get-account endpoint (checkLicenseStatus).
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
                "transformationId": "isEmailSecurityEnabled",
                "vendor": "Mimecast",
                "category": "emailsecurity"
            }
        }
    }


def extract_account_records(data):
    """
    The workflow merges all API method results. checkLicenseStatus stores its
    records under the key 'checkLicenseStatus'. Fall back to a top-level 'data'
    list if the method-keyed form is absent.
    """
    if isinstance(data, dict):
        if "checkLicenseStatus" in data:
            records = data["checkLicenseStatus"]
            if isinstance(records, list):
                return records
        if "data" in data:
            records = data["data"]
            if isinstance(records, list):
                return records
    if isinstance(data, list):
        return data
    return []


def is_email_security_package(packages):
    """
    Returns True when at least one package name indicates email security
    entitlement. Mimecast package names commonly contain terms like 'email',
    'gateway', 'secure', or 'full'. An empty packages list is treated as
    non-disqualifying when licensePurchased > 0.
    """
    if not isinstance(packages, list):
        return False
    email_keywords = ["email", "gateway", "secure", "full", "advanced", "mime"]
    for pkg in packages:
        pkg_lower = str(pkg).lower()
        for kw in email_keywords:
            if kw in pkg_lower:
                return True
    return False


def evaluate(data):
    """
    Core evaluation logic for isEmailSecurityEnabled.

    Pass conditions (any one is sufficient):
      1. licensePurchased > 0 AND a recognised email-security package is present.
      2. licensePurchased > 0 AND packages list is empty/absent (account exists
         and has purchased seats -- treat as provisioned).
      3. A 'services.emailSecurityEnabled' flag is explicitly True.
      4. The account record exists but zero licenses -- check commercialPackage field.
    """
    records = extract_account_records(data)

    if not records:
        return {
            "isEmailSecurityEnabled": False,
            "reason": "No account records returned from checkLicenseStatus"
        }

    account = records[0] if isinstance(records[0], dict) else {}

    license_purchased = account.get("licensePurchased", 0)
    license_used = account.get("licenseUsed", 0)
    packages = account.get("packages", [])
    account_type = str(account.get("type", "")).lower()
    account_code = account.get("accountCode", "")
    commercial_package = str(account.get("commercialPackage", "")).lower()

    # Check explicit services flag when present
    services = account.get("services", {})
    if isinstance(services, dict):
        explicit_flag = services.get("emailSecurityEnabled")
        if explicit_flag is True:
            return {
                "isEmailSecurityEnabled": True,
                "licensePurchased": license_purchased,
                "licenseUsed": license_used,
                "accountCode": account_code,
                "packageCount": len(packages) if isinstance(packages, list) else 0,
                "detectionMethod": "services.emailSecurityEnabled flag"
            }

    # Suspended / expired accounts are not considered enabled
    inactive_states = ["suspended", "trial_expired", "expired", "inactive", "closed"]
    for state in inactive_states:
        if state in account_type:
            return {
                "isEmailSecurityEnabled": False,
                "licensePurchased": license_purchased,
                "accountCode": account_code,
                "accountType": account_type,
                "reason": "Account is in an inactive state: " + account_type
            }

    # Licenses purchased with a matching package
    if license_purchased > 0 and is_email_security_package(packages):
        return {
            "isEmailSecurityEnabled": True,
            "licensePurchased": license_purchased,
            "licenseUsed": license_used,
            "accountCode": account_code,
            "packageCount": len(packages),
            "packages": packages,
            "detectionMethod": "licensePurchased + email security package match"
        }

    # Licenses purchased; packages list absent or unrecognised -- still treat as enabled
    if license_purchased > 0:
        return {
            "isEmailSecurityEnabled": True,
            "licensePurchased": license_purchased,
            "licenseUsed": license_used,
            "accountCode": account_code,
            "packageCount": len(packages) if isinstance(packages, list) else 0,
            "detectionMethod": "licensePurchased > 0 (packages not matched)"
        }

    # Account record exists but zero licenses -- check commercial package field
    if "full" in commercial_package or "email" in commercial_package:
        return {
            "isEmailSecurityEnabled": True,
            "licensePurchased": license_purchased,
            "accountCode": account_code,
            "commercialPackage": commercial_package,
            "detectionMethod": "commercialPackage indicates email security"
        }

    if account_code:
        return {
            "isEmailSecurityEnabled": False,
            "licensePurchased": license_purchased,
            "accountCode": account_code,
            "reason": "Account exists but no email security licenses or packages detected"
        }

    return {
        "isEmailSecurityEnabled": False,
        "reason": "Could not determine email security status from account data"
    }


def transform(input):
    criteriaKey = "isEmailSecurityEnabled"
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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "reason" and k != "error"}
        reason = eval_result.get("reason", "")
        detection_method = eval_result.get("detectionMethod", "")

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Mimecast Email Security is active and provisioned.")
            if detection_method:
                pass_reasons.append("Detection method: " + detection_method)
            license_purchased = eval_result.get("licensePurchased", 0)
            license_used = eval_result.get("licenseUsed", 0)
            if license_purchased:
                pass_reasons.append(
                    "Licenses purchased: " + str(license_purchased) +
                    ", in use: " + str(license_used)
                )
            packages = eval_result.get("packages", [])
            if packages:
                additional_findings.append("Detected packages: " + ", ".join([str(p) for p in packages]))
        else:
            fail_reasons.append("Mimecast Email Security does not appear to be enabled.")
            if reason:
                fail_reasons.append("Detail: " + reason)
            recommendations.append(
                "Verify the Mimecast account has an active Email Security subscription "
                "and that at least one license is purchased in the Administration Console."
            )
            recommendations.append(
                "Ensure the API credentials have the 'Account | Settings | Read' permission "
                "so that account and package entitlement data is returned."
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
