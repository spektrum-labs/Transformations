"""Transformation: confirmedLicensePurchased"""


def transform(api_response, settings=None):
    data_collection_errors = []
    validation_errors = []
    validation_warnings = []

    confirmed = False
    total_licenses = 0
    active_licenses = 0
    sku = None
    unlimited_licenses = False

    try:
        raw = api_response or {}
        data_block = raw.get("data", {})
        if isinstance(data_block, dict):
            sites = data_block.get("sites", [])
        else:
            sites = []

        for site in sites:
            site_sku = site.get("sku", "")
            site_state = site.get("state", "")
            site_active = site.get("activeLicenses", 0) or 0
            site_total = site.get("totalLicenses", 0) or 0
            site_unlimited = site.get("unlimitedLicenses", False) or False

            active_licenses += site_active
            total_licenses += site_total

            if site_sku and site_state == "active":
                confirmed = True
                sku = site_sku
                if site_unlimited:
                    unlimited_licenses = True

        if not sites:
            data_collection_errors.append("No sites returned from API")

    except Exception as e:
        data_collection_errors.append("Error processing API response: " + str(e))

    data_status = "success" if not data_collection_errors else "error"
    validation_status = "skipped"

    transformed_response = {
        "confirmedLicensePurchased": confirmed,
        "sku": sku,
        "activeLicenses": active_licenses,
        "totalLicenses": total_licenses,
        "unlimitedLicenses": unlimited_licenses,
    }

    return {
        "transformedResponse": transformed_response,
        "additionalInfo": {
            "dataCollection": {
                "status": data_status,
                "errors": data_collection_errors,
            },
            "validation": {
                "status": validation_status,
                "errors": validation_errors,
                "warnings": validation_warnings,
            },
        },
    }
