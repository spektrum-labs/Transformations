"""
Transformation: confirmedLicensePurchased
Vendor: SentinelOne
Category: epp
Method: getAccounts

Checks that at least one account has a Paid, active account type with valid
license entitlements (unlimited SKU, positive license count, or named bundles).
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    accounts = data.get("data") or []
    total_accounts = len(accounts)

    if total_accounts == 0:
        return create_response(
            result={
                "confirmedLicensePurchased": False,
                "accountCount": 0,
                "activeAccountCount": 0,
                "paidAccountCount": 0,
                "licensedBundles": [],
                "unlimitedSkuAccounts": 0,
            },
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No account records returned from the SentinelOne API. Cannot confirm a purchased license."],
            recommendations=["Verify that the API token has sufficient permissions to read account data, and that at least one account exists in the management console."],
            input_summary={"accountCount": 0},
            metadata={
                "transformationId": "confirmedLicensePurchased",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    paid_accounts = []
    active_accounts = []
    licensed_bundles = []
    unlimited_sku_accounts = []
    positive_license_accounts = []

    for account in accounts:
        account_type = account.get("accountType") or ""
        state = account.get("state") or ""
        name = account.get("name") or account.get("id") or "unknown"

        if account_type.lower() == "paid":
            paid_accounts.append(name)

        if state.lower() == "active":
            active_accounts.append(name)

        skus = account.get("skus") or []
        found_sku_entitlement = False
        for sku in skus:
            if sku.get("unlimited") is True:
                if name not in unlimited_sku_accounts:
                    unlimited_sku_accounts.append(name)
                found_sku_entitlement = True
                break
            sku_total = sku.get("totalLicenses") or 0
            if isinstance(sku_total, int) and sku_total > 0:
                if name not in positive_license_accounts:
                    positive_license_accounts.append(name)
                found_sku_entitlement = True
                break

        # Also accept totalLicenses == -1 at account level (means unlimited)
        if not found_sku_entitlement:
            acct_total_licenses = account.get("totalLicenses")
            if isinstance(acct_total_licenses, int) and acct_total_licenses == -1:
                if name not in unlimited_sku_accounts:
                    unlimited_sku_accounts.append(name)

        bundles = (account.get("licenses") or {}).get("bundles") or []
        for bundle in bundles:
            display = bundle.get("displayName") or bundle.get("name") or ""
            if display and display not in licensed_bundles:
                licensed_bundles.append(display)

    has_paid = len(paid_accounts) > 0
    has_active = len(active_accounts) > 0
    has_entitlement = (
        len(unlimited_sku_accounts) > 0
        or len(positive_license_accounts) > 0
        or len(licensed_bundles) > 0
    )

    confirmed = has_paid and has_active and has_entitlement

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        bundle_str = ", ".join(licensed_bundles) if licensed_bundles else "none listed"
        unlimited_str = ", ".join(unlimited_sku_accounts) if unlimited_sku_accounts else "none"
        pass_reasons.append(
            f"Account(s) {paid_accounts} have accountType='Paid' and state='active', "
            f"confirming an active subscription. "
            f"Unlimited SKU entitlement on account(s): {unlimited_str}. "
            f"Licensed bundles: {bundle_str}."
        )
    else:
        if not has_paid:
            observed_types = [a.get("accountType") for a in accounts]
            fail_reasons.append(
                f"No account with accountType='Paid' found among {total_accounts} account(s). "
                f"Account types observed: {observed_types}."
            )
            recommendations.append("Purchase a SentinelOne license and ensure the account type is set to 'Paid' in the management console.")
        if not has_active:
            observed_states = [a.get("state") for a in accounts]
            fail_reasons.append(
                f"No account with state='active' found among {total_accounts} account(s). "
                f"States observed: {observed_states}."
            )
            recommendations.append("Activate the SentinelOne account in the management console or contact SentinelOne support to resolve the inactive account state.")
        if not has_entitlement:
            fail_reasons.append(
                "No valid license entitlement found: no unlimited SKUs, no positive totalLicenses, "
                "and no named license bundles present on any account."
            )
            recommendations.append("Assign a valid SentinelOne SKU or bundle to the account to establish license entitlement.")

    return create_response(
        result={
            "confirmedLicensePurchased": confirmed,
            "accountCount": total_accounts,
            "activeAccountCount": len(active_accounts),
            "paidAccountCount": len(paid_accounts),
            "licensedBundles": licensed_bundles,
            "unlimitedSkuAccounts": len(unlimited_sku_accounts),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountCount": total_accounts,
            "paidAccounts": paid_accounts,
            "activeAccounts": active_accounts,
            "licensedBundles": licensed_bundles,
            "unlimitedSkuAccounts": unlimited_sku_accounts,
        },
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
