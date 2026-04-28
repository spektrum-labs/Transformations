"""Transformation: confirmedLicensePurchased"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}
    data = api_response.get("data") or []

    confirmed = False
    license_details = []

    for account in data:
        account_type = account.get("accountType") or ""
        state = account.get("state") or ""
        total_licenses = account.get("totalLicenses")
        skus = account.get("skus") or []
        licenses = account.get("licenses") or {}
        bundles = licenses.get("bundles") or []

        has_active_license = False

        # totalLicenses == -1 indicates unlimited seats
        if total_licenses is not None and (total_licenses > 0 or total_licenses == -1):
            has_active_license = True

        # Check individual SKUs for unlimited flag or non-zero seat count
        for sku in skus:
            if sku.get("unlimited") is True or (sku.get("totalLicenses") or 0) > 0:
                has_active_license = True
                break

        # Non-empty bundles array also confirms a license bundle is present
        if bundles:
            has_active_license = True

        is_active_state = state.lower() == "active"

        if is_active_state and has_active_license:
            confirmed = True

        license_details.append({
            "accountId": account.get("id") or "",
            "accountName": account.get("name") or "",
            "accountType": account_type,
            "state": state,
            "totalLicenses": total_licenses,
            "hasActiveLicense": has_active_license,
        })

    return {
        "transformedResponse": {
            "confirmedLicensePurchased": confirmed,
            "licenseDetails": license_details,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
