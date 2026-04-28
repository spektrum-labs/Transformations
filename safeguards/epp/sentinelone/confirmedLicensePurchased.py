"""Transformation: confirmedLicensePurchased"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}
    data = api_response.get("data") or []

    confirmed = False
    account_name = None
    account_type = None
    account_state = None
    billing_mode = None
    license_bundles = []
    skus = []
    expiration = None
    unlimited_expiration = False
    errors = []

    if not data:
        errors.append("No accounts returned from API")
    else:
        account = data[0] if isinstance(data, list) and len(data) > 0 else {}
        account = account if isinstance(account, dict) else {}

        account_name = account.get("name")
        account_type = account.get("accountType")
        account_state = account.get("state")
        billing_mode = account.get("billingMode")
        expiration = account.get("expiration")
        unlimited_expiration = bool(account.get("unlimitedExpiration", False))

        licenses_obj = account.get("licenses") or {}
        licenses_obj = licenses_obj if isinstance(licenses_obj, dict) else {}
        bundles_raw = licenses_obj.get("bundles") or []
        license_bundles = [
            b.get("displayName") or b.get("name", "")
            for b in bundles_raw
            if isinstance(b, dict)
        ]

        skus_raw = account.get("skus") or []
        skus = [
            {
                "type": s.get("type"),
                "totalLicenses": s.get("totalLicenses"),
                "unlimited": s.get("unlimited", False),
            }
            for s in skus_raw
            if isinstance(s, dict)
        ]

        has_active_state = (account_state or "").lower() == "active"
        has_paid_type = (account_type or "").lower() not in ("", "trial")
        has_license = bool(license_bundles) or bool(skus)

        confirmed = has_active_state and has_paid_type and has_license

    return {
        "transformedResponse": {
            "confirmedLicensePurchased": confirmed,
            "accountName": account_name,
            "accountType": account_type,
            "accountState": account_state,
            "billingMode": billing_mode,
            "expiration": expiration,
            "unlimitedExpiration": unlimited_expiration,
            "licenseBundles": license_bundles,
            "skus": skus,
        },
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if not errors else "failure",
                "errors": errors,
            },
            "validation": {
                "status": "skipped",
                "errors": [],
                "warnings": [],
            },
        },
    }
