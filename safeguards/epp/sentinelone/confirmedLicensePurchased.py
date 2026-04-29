"""Transformation: confirmedLicensePurchased — checks that a valid SentinelOne license is purchased and active."""
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
            result={"confirmedLicensePurchased": False, "totalAccounts": 0, "activePaidAccounts": 0},
            validation=validation,
            fail_reasons=["No accounts found in the SentinelOne API response. Cannot confirm a valid license is purchased."],
            recommendations=["Verify that the API token has sufficient permissions to read account data and that the account is properly set up in SentinelOne."],
            input_summary={"totalAccounts": 0, "activePaidAccounts": 0},
            metadata={"transformationId": "confirmedLicensePurchased", "vendor": "SentinelOne", "category": "epp"},
        )

    total_accounts = len(accounts)
    active_paid_accounts = []
    all_findings = []

    for account in accounts:
        account_name = account.get("name") or "Unknown"
        account_state = account.get("state") or ""
        account_type = account.get("accountType") or ""
        billing_mode = account.get("billingMode") or ""
        total_licenses = account.get("totalLicenses")
        active_agents = account.get("activeAgents") or 0

        skus = account.get("skus") or []
        licenses = account.get("licenses") or {}
        bundles = licenses.get("bundles") or []

        is_active = account_state.lower() == "active"
        is_paid = account_type.lower() == "paid"

        has_unlimited_sku = False
        has_nonzero_sku = False
        sku_details = []
        for sku in skus:
            sku_type = sku.get("type") or "Unknown"
            sku_unlimited = sku.get("unlimited") or False
            sku_total = sku.get("totalLicenses") or 0
            if sku_unlimited:
                has_unlimited_sku = True
            if sku_total > 0:
                has_nonzero_sku = True
            sku_details.append(sku_type + "(unlimited=" + str(sku_unlimited) + ", totalLicenses=" + str(sku_total) + ")")

        bundle_names = [b.get("displayName") or b.get("name") or "Unknown" for b in bundles]

        # totalLicenses=-1 means unlimited; unlimited SKU or positive seat count also valid
        has_license = (
            (total_licenses is not None and total_licenses != 0)
            or has_unlimited_sku
            or has_nonzero_sku
        )

        finding = (
            "Account '" + account_name + "': state=" + account_state
            + ", accountType=" + account_type
            + ", billingMode=" + billing_mode
            + ", totalLicenses=" + str(total_licenses)
            + ", activeAgents=" + str(active_agents)
        )
        if bundle_names:
            finding = finding + ", bundles=[" + ", ".join(bundle_names) + "]"
        if sku_details:
            finding = finding + ", skus=[" + ", ".join(sku_details) + "]"
        all_findings.append(finding)

        if is_active and is_paid and has_license:
            active_paid_accounts.append({
                "name": account_name,
                "state": account_state,
                "accountType": account_type,
                "billingMode": billing_mode,
                "totalLicenses": total_licenses,
                "bundleNames": bundle_names,
                "skuDetails": sku_details,
                "activeAgents": active_agents,
            })

    confirmed = len(active_paid_accounts) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        for acc in active_paid_accounts:
            parts = [
                "Account '" + acc["name"] + "' has a valid paid license",
                "state=" + acc["state"],
                "accountType=" + acc["accountType"],
                "billingMode=" + acc["billingMode"],
                "totalLicenses=" + str(acc["totalLicenses"]),
                "activeAgents=" + str(acc["activeAgents"]),
            ]
            if acc["bundleNames"]:
                parts.append("bundles=[" + ", ".join(acc["bundleNames"]) + "]")
            if acc["skuDetails"]:
                parts.append("skus=[" + ", ".join(acc["skuDetails"]) + "]")
            pass_reasons.append(", ".join(parts))
    else:
        for finding in all_findings:
            fail_reasons.append("No valid paid active license found. " + finding)
        recommendations.append(
            "Ensure the SentinelOne account has an active paid subscription. "
            "Check that account state='active', accountType='Paid', and at least one SKU "
            "has unlimited=true or totalLicenses > 0."
        )

    return create_response(
        result={
            "confirmedLicensePurchased": confirmed,
            "totalAccounts": total_accounts,
            "activePaidAccounts": len(active_paid_accounts),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAccounts": total_accounts,
            "activePaidAccounts": len(active_paid_accounts),
        },
        additional_findings=all_findings,
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
