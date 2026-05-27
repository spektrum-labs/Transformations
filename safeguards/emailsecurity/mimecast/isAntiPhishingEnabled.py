
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    accounts = data.get("data") or []

    if not accounts:
        return create_response(
            result={
                "isAntiPhishingEnabled": False,
                "impersonationProtectionLicensed": False,
                "urlProtectionLicensed": False,
                "businessEmailCompromiseLicensed": False,
                "totalPackages": 0,
            },
            validation=validation,
            fail_reasons=["No account data returned from the getAccount endpoint; cannot confirm anti-phishing protection is active."],
            recommendations=["Verify Mimecast API credentials and account access, then re-evaluate."],
            input_summary={"accountCount": 0, "antiPhishingPackagesFound": []},
            metadata={
                "transformationId": "isAntiPhishingEnabled",
                "vendor": "Mimecast",
                "category": "emailsecurity",
            },
        )

    account = accounts[0] if isinstance(accounts[0], dict) else {}
    packages = account.get("packages") or []
    account_name = account.get("accountName") or "unknown"

    IMPERSONATION_PROTECTION = "Impersonation Protection [1060]"
    URL_PROTECTION = "URL Protection (Site) [1043]"
    BEC = "Business Email Compromise [1109]"

    has_impersonation = IMPERSONATION_PROTECTION in packages
    has_url_protection = URL_PROTECTION in packages
    has_bec = BEC in packages

    is_enabled = has_impersonation

    found_packages = []
    if has_impersonation:
        found_packages.append(IMPERSONATION_PROTECTION)
    if has_url_protection:
        found_packages.append(URL_PROTECTION)
    if has_bec:
        found_packages.append(BEC)

    if is_enabled:
        pass_reasons = [
            f"Account '{account_name}' has 'Impersonation Protection [1060]' in the licensed packages array, confirming TTP Impersonation Protection (anti-phishing) is active."
        ]
        if has_url_protection:
            pass_reasons.append("'URL Protection (Site) [1043]' is also licensed, providing additional phishing URL blocking coverage.")
        if has_bec:
            pass_reasons.append("'Business Email Compromise [1109]' is also licensed, extending anti-phishing protection to BEC-style attacks.")
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Account '{account_name}' does not include 'Impersonation Protection [1060]' in the licensed packages array. TTP Impersonation Protection (anti-phishing) is not confirmed as active."
        ]
        recommendations = [
            "License and enable Impersonation Protection (package ID 1060) in Mimecast to activate anti-phishing email filtering against display-name spoofing and targeted threat dictionary attacks."
        ]

    return create_response(
        result={
            "isAntiPhishingEnabled": is_enabled,
            "impersonationProtectionLicensed": has_impersonation,
            "urlProtectionLicensed": has_url_protection,
            "businessEmailCompromiseLicensed": has_bec,
            "totalPackages": len(packages),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountName": account_name,
            "totalPackages": len(packages),
            "antiPhishingPackagesFound": found_packages,
        },
        metadata={
            "transformationId": "isAntiPhishingEnabled",
            "vendor": "Mimecast",
            "category": "emailsecurity",
        },
    )
