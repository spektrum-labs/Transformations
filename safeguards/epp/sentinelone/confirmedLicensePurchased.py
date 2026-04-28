"""Transformation: confirmedLicensePurchased"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}
    data = api_response.get("data") or []

    confirmed = False
    license_details = []

    for account in data:
        if not isinstance(account, dict):
            continue

        state = account.get("state") or ""
        account_type = account.get("accountType") or ""
        skus = account.get("skus") or []
        total_licenses = account.get("totalLicenses")

        # Account must be in active state
        is_active = state.lower() == "active"

        # Check individual SKUs for unlimited flag or positive license count
        has_valid_sku = False
        for sku in skus:
            if not isinstance(sku, dict):
                continue
            sku_unlimited = sku.get("unlimited") or False
            sku_total = sku.get("totalLicenses") or 0
            if sku_unlimited or sku_total > 0:
                has_valid_sku = True
                break

        # Account-level totalLicenses: -1 means unlimited, >0 means capped seats, 0 means none
        account_level_valid = (total_licenses is not None and total_licenses != 0)

        if is_active and (has_valid_sku or account_level_valid):
            confirmed = True

        license_details.append({
            "accountId": account.get("id") or "",
            "accountName": account.get("name") or "",
            "state": state,
            "accountType": account_type,
            "totalLicenses": total_licenses,
            "skuCount": len(skus),
        })

    return {
        "transformedResponse": {
            "confirmedLicensePurchased": confirmed,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {
                "status": "skipped",
                "errors": [],
                "warnings": [],
            },
            "licenseDetails": license_details,
        },
    }
