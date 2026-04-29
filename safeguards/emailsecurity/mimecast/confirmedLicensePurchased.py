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

    account_list = data.get("data") or []
    meta = data.get("meta") or {}
    fail_list = data.get("fail") or []

    meta_status = meta.get("status") if isinstance(meta, dict) else None
    has_account = len(account_list) > 0
    has_failures = len(fail_list) > 0

    # Pull first account record details for evidence
    account = account_list[0] if has_account else {}
    account_name = account.get("accountName") or "unknown"
    account_code = account.get("accountCode") or "unknown"
    packages = account.get("packages") or []
    package_count = len(packages)

    # A valid license is confirmed when:
    # - API returned status 200
    # - data array is non-empty (account record exists)
    # - fail array is empty
    license_purchased = (meta_status == 200 and has_account and not has_failures)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if license_purchased:
        pass_reasons.append(
            f"Mimecast API returned HTTP 200 with a populated account record "
            f"(accountCode={account_code}, accountName={account_name}). "
            f"Account has {package_count} provisioned packages and no failure entries, "
            f"confirming a valid, active Mimecast license."
        )
    else:
        if meta_status != 200:
            fail_reasons.append(
                f"API response meta.status was {meta_status} instead of 200, "
                f"indicating the account could not be retrieved."
            )
        if not has_account:
            fail_reasons.append(
                "The data array in the API response was empty — no account record returned."
            )
        if has_failures:
            fail_reasons.append(
                f"The fail array contained {len(fail_list)} error(s), indicating the account "
                f"request did not complete successfully."
            )
        recommendations.append(
            "Verify that the Mimecast OAuth credentials (clientId / clientSecret) are valid "
            "and that the account has an active Mimecast subscription."
        )

    return create_response(
        result={
            "confirmedLicensePurchased": license_purchased,
            "accountCode": account_code,
            "accountName": account_name,
            "packageCount": package_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "metaStatus": meta_status,
            "accountRecordCount": len(account_list),
            "failCount": len(fail_list),
            "packageCount": package_count,
        },
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "Mimecast",
            "category": "emailsecurity",
        },
    )
