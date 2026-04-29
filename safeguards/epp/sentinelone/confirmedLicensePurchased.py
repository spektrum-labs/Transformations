"""Transformation: confirmedLicensePurchased — SentinelOne getAccounts"""
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
    total_accounts = len(accounts)

    if total_accounts == 0:
        return create_response(
            result={
                "confirmedLicensePurchased": False,
                "totalAccounts": 0,
                "activeAccountsWithLicense": 0,
            },
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No accounts returned by the API — unable to confirm a purchased license."],
            recommendations=["Verify that the API token has permission to read account data and that at least one account exists."],
            input_summary={"totalAccounts": 0},
            metadata={
                "transformationId": "confirmedLicensePurchased",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    active_accounts_with_license = []
    findings = []

    for account in accounts:
        account_name = account.get("name") or account.get("id") or "unknown"
        state = account.get("state") or ""
        account_type = account.get("accountType") or ""
        billing_mode = account.get("billingMode") or ""
        total_licenses = account.get("totalLicenses")
        unlimited_expiration = account.get("unlimitedExpiration") or False
        expiration = account.get("expiration")

        licenses = account.get("licenses") or {}
        bundles = licenses.get("bundles") or []
        skus = account.get("skus") or []

        # Determine if any sku or bundle has a valid license
        has_unlimited_sku = any(s.get("unlimited") is True for s in skus)
        has_unlimited_licenses = (total_licenses is not None and total_licenses == -1)
        has_paid_bundles = len(bundles) > 0
        has_positive_licenses = (total_licenses is not None and total_licenses > 0)

        license_valid = has_unlimited_sku or has_unlimited_licenses or has_positive_licenses or has_paid_bundles
        account_active = (state.lower() == "active")

        bundle_names = [b.get("displayName") or b.get("name") or "" for b in bundles]
        sku_types = [s.get("type") or "" for s in skus]

        finding = (
            f"Account '{account_name}': state={state}, accountType={account_type}, "
            f"billingMode={billing_mode}, totalLicenses={total_licenses}, "
            f"bundles={bundle_names}, skus={sku_types}, "
            f"unlimitedExpiration={unlimited_expiration}"
        )
        findings.append(finding)

        if account_active and license_valid:
            active_accounts_with_license.append(account_name)

    confirmed = len(active_accounts_with_license) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        pass_reasons.append(
            f"{len(active_accounts_with_license)} of {total_accounts} account(s) "
            f"confirmed with an active, purchased license: {active_accounts_with_license}."
        )
    else:
        fail_reasons.append(
            f"None of the {total_accounts} account(s) returned have both state='active' "
            f"and a valid license bundle or SKU."
        )
        recommendations.append(
            "Ensure the SentinelOne account is in 'active' state with at least one "
            "purchased license bundle (e.g., 'Endpoint Security - Complete') or unlimited SKU."
        )

    return create_response(
        result={
            "confirmedLicensePurchased": confirmed,
            "totalAccounts": total_accounts,
            "activeAccountsWithLicense": len(active_accounts_with_license),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAccounts": total_accounts,
            "activeAccountsWithLicense": len(active_accounts_with_license),
        },
        additional_findings=findings,
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
