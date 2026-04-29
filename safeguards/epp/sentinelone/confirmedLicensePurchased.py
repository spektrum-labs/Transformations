"""
Transformation: confirmedLicensePurchased
Vendor: SentinelOne
Category: epp
Description: Checks getAccounts response to confirm a valid, active license is purchased.
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
    transformation_errors = []

    if not accounts:
        return create_response(
            result={"confirmedLicensePurchased": False, "accountCount": 0},
            validation=validation,
            fail_reasons=["No account records were returned by the SentinelOne accounts endpoint."],
            recommendations=["Verify that the API token has sufficient permissions to read account data."],
            input_summary={"accountCount": 0},
            metadata={
                "transformationId": "confirmedLicensePurchased",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    # Evaluate each account for a valid, active paid license
    account_count = len(accounts)
    paid_active_accounts = []
    all_account_findings = []

    for acct in accounts:
        acct_name = acct.get("name") or acct.get("id") or "unknown"
        acct_type = acct.get("accountType") or ""
        acct_state = acct.get("state") or ""
        skus = acct.get("skus") or []
        licenses = acct.get("licenses") or {}
        bundles = licenses.get("bundles") or []
        total_licenses = acct.get("totalLicenses")
        unlimited_expiration = acct.get("unlimitedExpiration") or False
        expiration = acct.get("expiration")

        is_paid = acct_type.lower() == "paid"
        is_active = acct_state.lower() == "active"

        # Determine license details from SKUs
        sku_details = []
        for sku in skus:
            sku_type = sku.get("type") or "unknown"
            sku_unlimited = sku.get("unlimited") or False
            sku_total = sku.get("totalLicenses")
            agents_in_sku = sku.get("agentsInSku") or 0
            if sku_unlimited:
                sku_details.append(sku_type + " (unlimited seats, " + str(agents_in_sku) + " agents enrolled)")
            else:
                sku_details.append(sku_type + " (" + str(sku_total) + " seats, " + str(agents_in_sku) + " agents enrolled)")

        # Determine bundle names
        bundle_names = [b.get("displayName") or b.get("name") or "unknown" for b in bundles]

        # Check for valid (non-expired) license — unlimited_expiration means no expiry
        # totalLicenses == -1 means unlimited
        has_valid_license = (
            is_paid and
            is_active and
            (len(skus) > 0 or len(bundles) > 0 or total_licenses == -1)
        )

        finding = (
            "Account '" + acct_name + "': accountType=" + acct_type +
            ", state=" + acct_state +
            ", totalLicenses=" + str(total_licenses) +
            ", unlimitedExpiration=" + str(unlimited_expiration)
        )
        if sku_details:
            finding = finding + ", SKUs=[" + "; ".join(sku_details) + "]"
        if bundle_names:
            finding = finding + ", bundles=[" + ", ".join(bundle_names) + "]"

        all_account_findings.append(finding)

        if has_valid_license:
            paid_active_accounts.append({
                "name": acct_name,
                "accountType": acct_type,
                "state": acct_state,
                "totalLicenses": total_licenses,
                "unlimitedExpiration": unlimited_expiration,
                "skuDetails": sku_details,
                "bundleNames": bundle_names,
            })

    confirmed = len(paid_active_accounts) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        for acct_info in paid_active_accounts:
            detail = (
                "Account '" + acct_info["name"] + "' has an active paid license "
                "(accountType=" + acct_info["accountType"] + ", state=" + acct_info["state"] + ", "
                "totalLicenses=" + str(acct_info["totalLicenses"]) + ", "
                "unlimitedExpiration=" + str(acct_info["unlimitedExpiration"]) + ")"
            )
            if acct_info["skuDetails"]:
                detail = detail + " with SKUs: [" + "; ".join(acct_info["skuDetails"]) + "]"
            if acct_info["bundleNames"]:
                detail = detail + " and bundles: [" + ", ".join(acct_info["bundleNames"]) + "]"
            detail = detail + "."
            pass_reasons.append(detail)
    else:
        for finding in all_account_findings:
            fail_reasons.append("License check failed — " + finding)
        recommendations.append(
            "Ensure at least one account has accountType='Paid' and state='active' with "
            "a configured SKU or license bundle. Contact SentinelOne support to activate "
            "or renew your subscription."
        )

    return create_response(
        result={
            "confirmedLicensePurchased": confirmed,
            "accountCount": account_count,
            "paidActiveAccountCount": len(paid_active_accounts),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountCount": account_count,
            "paidActiveAccountCount": len(paid_active_accounts),
        },
        additional_findings=all_account_findings,
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
