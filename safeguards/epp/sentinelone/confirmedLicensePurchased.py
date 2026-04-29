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
    accounts = accounts if isinstance(accounts, list) else []

    if not accounts:
        return create_response(
            result={"confirmedLicensePurchased": False},
            validation=validation,
            fail_reasons=["No account records returned from getAccounts endpoint."],
            recommendations=["Verify API credentials and account provisioning in SentinelOne."],
            input_summary={"accountCount": 0},
            metadata={
                "transformationId": "confirmedLicensePurchased",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    # Evaluate each account for a valid active license
    paid_active_accounts = []
    unlimited_accounts = []
    bundle_names = []
    sku_types = []
    account_types = []
    account_states = []

    for account in accounts:
        acct_type = account.get("accountType") or ""
        state = account.get("state") or ""
        account_types.append(acct_type)
        account_states.append(state)

        # Check skus for unlimited or positive license counts
        skus = account.get("skus") or []
        skus = skus if isinstance(skus, list) else []
        for sku in skus:
            sku_type = sku.get("type") or ""
            if sku_type and sku_type not in sku_types:
                sku_types.append(sku_type)
            unlimited = sku.get("unlimited") or False
            total_licenses = sku.get("totalLicenses") or 0
            if unlimited or total_licenses > 0:
                if acct_type.lower() == "paid" and state.lower() == "active":
                    if account not in paid_active_accounts:
                        paid_active_accounts.append(account)

        # Check licenses.bundles
        licenses_obj = account.get("licenses") or {}
        licenses_obj = licenses_obj if isinstance(licenses_obj, dict) else {}
        bundles = licenses_obj.get("bundles") or []
        bundles = bundles if isinstance(bundles, list) else []
        for bundle in bundles:
            bname = bundle.get("displayName") or bundle.get("name") or ""
            if bname and bname not in bundle_names:
                bundle_names.append(bname)

        # Also check unlimited flags at account level
        unlimited_complete = account.get("unlimitedComplete") or False
        unlimited_control = account.get("unlimitedControl") or False
        unlimited_core = account.get("unlimitedCore") or False
        if (unlimited_complete or unlimited_control or unlimited_core) and state.lower() == "active":
            if account not in unlimited_accounts:
                unlimited_accounts.append(account)

    # A license is confirmed if any account is Paid + active with unlimited or purchased seats
    confirmed = len(paid_active_accounts) > 0 or len(unlimited_accounts) > 0

    total_accounts = len(accounts)
    confirmed_count = len(paid_active_accounts) if paid_active_accounts else len(unlimited_accounts)

    # Build human-readable strings without .format()
    sku_types_str = ", ".join(sku_types) if sku_types else "N/A"
    bundle_names_str = ", ".join(bundle_names) if bundle_names else "N/A"
    account_types_str = ", ".join(account_types) if account_types else "N/A"
    account_states_str = ", ".join(account_states) if account_states else "N/A"

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        pass_reasons.append(
            str(confirmed_count) + " of " + str(total_accounts) +
            " account(s) confirmed as Paid and active with a valid license. " +
            "Account type(s): " + account_types_str + ". " +
            "Account state(s): " + account_states_str + ". " +
            "SKU type(s): " + sku_types_str + ". " +
            "License bundle(s): " + bundle_names_str + "."
        )
    else:
        fail_reasons.append(
            "No accounts found with a Paid accountType and active state with valid license seats. " +
            "Account type(s) found: " + account_types_str + ". " +
            "Account state(s) found: " + account_states_str + "."
        )
        recommendations.append(
            "Purchase a SentinelOne license (Complete, Control, or Core SKU) and ensure the account state is active."
        )

    return create_response(
        result={
            "confirmedLicensePurchased": confirmed,
            "totalAccounts": total_accounts,
            "confirmedAccounts": confirmed_count,
            "skuTypes": sku_types_str,
            "licenseBundles": bundle_names_str,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAccounts": total_accounts,
            "confirmedAccounts": confirmed_count,
            "skuTypes": sku_types,
            "licenseBundles": bundle_names,
        },
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
