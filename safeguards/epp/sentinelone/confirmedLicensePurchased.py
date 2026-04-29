
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
                "confirmedLicensePurchased": False,
                "totalAccounts": 0,
                "activeAccounts": 0,
                "paidAccounts": 0,
                "licensedBundles": [],
            },
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No account records returned from the API. Unable to confirm a valid license exists."],
            recommendations=[
                "Verify the API token has sufficient permissions to read account information, "
                "and that at least one account exists."
            ],
            input_summary={"totalAccounts": 0, "activeAccounts": 0},
            metadata={
                "transformationId": "confirmedLicensePurchased",
                "vendor": "SentinelOne",
                "category": "epp",
            }
        )

    license_confirmed = False
    active_accounts = 0
    paid_accounts = 0
    unlimited_accounts = 0
    licensed_bundle_names = []

    for account in accounts:
        state = account.get("state") or ""
        account_type = account.get("accountType") or ""
        total_licenses = account.get("totalLicenses")
        unlimited_complete = account.get("unlimitedComplete") or False
        unlimited_control = account.get("unlimitedControl") or False
        unlimited_core = account.get("unlimitedCore") or False
        skus = account.get("skus") or []
        licenses_obj = account.get("licenses") or {}
        bundles = licenses_obj.get("bundles") or []

        if state == "active":
            active_accounts = active_accounts + 1

        if account_type == "Paid":
            paid_accounts = paid_accounts + 1

        has_unlimited = unlimited_complete or unlimited_control or unlimited_core
        if not has_unlimited:
            for sku in skus:
                if sku.get("unlimited"):
                    has_unlimited = True
                    break

        # totalLicenses == -1 means unlimited in the SentinelOne API
        has_licenses = has_unlimited or (total_licenses is not None and total_licenses != 0)

        if has_unlimited:
            unlimited_accounts = unlimited_accounts + 1

        for bundle in bundles:
            bundle_name = bundle.get("displayName") or bundle.get("name") or ""
            if bundle_name and bundle_name not in licensed_bundle_names:
                licensed_bundle_names.append(bundle_name)

        if state == "active" and has_licenses:
            license_confirmed = True

    total_accounts = len(accounts)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if license_confirmed:
        reason_parts = []
        if paid_accounts > 0:
            reason_parts.append(f"{paid_accounts} account(s) with accountType='Paid'")
        if unlimited_accounts > 0:
            reason_parts.append(f"{unlimited_accounts} account(s) with unlimited license entitlement")
        if licensed_bundle_names:
            bundle_str = ", ".join(licensed_bundle_names)
            reason_parts.append(f"licensed bundle(s): {bundle_str}")
        summary = "; ".join(reason_parts) if reason_parts else "active state with valid license entitlement"
        pass_reasons.append(
            f"Valid license confirmed across {active_accounts} active account(s) "
            f"(of {total_accounts} total): {summary}."
        )
    else:
        fail_reasons.append(
            f"No active accounts with valid license entitlement found across {total_accounts} account(s) examined "
            f"(active={active_accounts}, paid={paid_accounts}, unlimited={unlimited_accounts})."
        )
        recommendations.append(
            "Ensure at least one SentinelOne account is in 'active' state with a purchased license "
            "(totalLicenses > 0, totalLicenses = -1 for unlimited, or skus[*].unlimited = true)."
        )

    return create_response(
        result={
            "confirmedLicensePurchased": license_confirmed,
            "totalAccounts": total_accounts,
            "activeAccounts": active_accounts,
            "paidAccounts": paid_accounts,
            "licensedBundles": licensed_bundle_names,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAccounts": total_accounts,
            "activeAccounts": active_accounts,
        },
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "SentinelOne",
            "category": "epp",
        }
    )
