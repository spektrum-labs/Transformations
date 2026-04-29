"""Transformation: isEmailLoggingEnabled
Checks whether the Enhanced Logging package (1061) is provisioned on the
Mimecast account, indicating email security logs can be integrated with SIEM.
"""
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


ENHANCED_LOGGING_CODE = "1061"


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    # The account data is in data["data"][0]
    account_list = data.get("data") or []
    account = account_list[0] if account_list and isinstance(account_list[0], dict) else {}

    packages = account.get("packages") or []
    account_name = account.get("accountName") or "Unknown"
    account_code = account.get("accountCode") or "Unknown"

    # Check for Enhanced Logging package [1061]
    enhanced_logging_found = False
    matched_package = None
    for pkg in packages:
        if isinstance(pkg, str) and ENHANCED_LOGGING_CODE in pkg:
            enhanced_logging_found = True
            matched_package = pkg
            break

    total_packages = len(packages)

    if enhanced_logging_found:
        pass_reasons = [
            f"Account '{account_name}' (code: {account_code}) has the '{matched_package}' package provisioned, "
            f"confirming Enhanced Logging is enabled. "
            f"This allows email security log data to be forwarded to a SIEM. "
            f"({total_packages} total packages found on the account.)"
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Account '{account_name}' (code: {account_code}) does not have the "
            f"'Enhanced Logging [1061]' package in its provisioned packages list "
            f"({total_packages} packages inspected). "
            f"Email security log forwarding to a SIEM cannot be confirmed."
        ]
        recommendations = [
            "Contact your Mimecast account representative to provision the 'Enhanced Logging [1061]' "
            "package, then configure the SIEM integration via the Mimecast Cloud Gateway or "
            "third-party connector to enable email security log streaming."
        ]

    api_errors = []
    fail_list = data.get("fail") or []
    if fail_list:
        for f in fail_list:
            if isinstance(f, dict):
                errs = f.get("errors") or []
                for e in errs:
                    if isinstance(e, dict):
                        api_errors.append(e.get("message") or str(e))

    return create_response(
        result={
            "isEmailLoggingEnabled": enhanced_logging_found,
            "enhancedLoggingPackageFound": matched_package,
            "totalPackages": total_packages,
            "accountName": account_name,
            "accountCode": account_code,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountName": account_name,
            "accountCode": account_code,
            "totalPackages": total_packages,
            "enhancedLoggingFound": enhanced_logging_found,
        },
        metadata={
            "transformationId": "isEmailLoggingEnabled",
            "vendor": "Mimecast",
            "category": "emailsecurity",
        },
        api_errors=api_errors,
    )
