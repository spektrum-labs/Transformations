"""Transformation: confirmedLicensePurchased — Mimecast getAccount"""
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

    # The Mimecast getAccount response wraps account records in a top-level "data" list
    account_list = data.get("data") or []
    fail_list = data.get("fail") or []
    meta = data.get("meta") or {}
    meta_status = meta.get("status") if isinstance(meta, dict) else None

    # API-level errors surfaced in the "fail" array
    api_errors = []
    if fail_list:
        api_errors = [str(f) for f in fail_list]

    if not account_list:
        # No account data returned — cannot confirm license
        return create_response(
            result={
                "confirmedLicensePurchased": False,
                "packageCount": 0,
                "accountCode": None,
            },
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No account data was returned in the getAccount response. Cannot confirm a valid Mimecast license."],
            recommendations=["Verify that the API credentials have the Accounts | Dashboard | Read scope and that the account is active."],
            input_summary={"accountCount": 0, "metaStatus": meta_status, "failCount": len(fail_list)},
            api_errors=api_errors,
            metadata={
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Mimecast",
                "category": "Email Security",
            },
        )

    account = account_list[0] if isinstance(account_list[0], dict) else {}
    account_code = account.get("accountCode") or ""
    account_name = account.get("accountName") or ""
    packages = account.get("packages") or []
    package_count = len(packages)

    license_purchased = package_count > 0

    if license_purchased:
        pass_reasons = [
            f"Mimecast account '{account_name}' (code: {account_code}) returned a valid getAccount response with {package_count} licensed packages, confirming an active Mimecast license is purchased."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Mimecast account '{account_name}' (code: {account_code}) returned a valid response but the packages array is empty, indicating no licensed products were found."
        ]
        recommendations = [
            "Contact Mimecast support to verify the account's license status and ensure at least one product package is assigned."
        ]

    return create_response(
        result={
            "confirmedLicensePurchased": license_purchased,
            "packageCount": package_count,
            "accountCode": account_code,
            "accountName": account_name,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountCount": len(account_list),
            "accountCode": account_code,
            "packageCount": package_count,
            "metaStatus": meta_status,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "Mimecast",
            "category": "Email Security",
        },
    )
