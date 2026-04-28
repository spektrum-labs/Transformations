"""Transformation: confirmedLicensePurchased
Vendor: SentinelOne
Method: getSites
Criterion: Ensure a valid license is purchased and active
"""


def transform(api_response):
    data_collection_errors = []
    validation_errors = []
    validation_warnings = []

    sites = []
    try:
        raw = api_response if isinstance(api_response, dict) else {}
        data = raw.get("data", {})
        # getSites: data may be a dict with a "sites" key, or a list directly
        if isinstance(data, dict):
            sites = data.get("sites", [])
        elif isinstance(data, list):
            sites = data
    except Exception as e:
        data_collection_errors.append("Failed to extract sites: " + str(e))

    confirmed = False
    total_sites = len(sites)
    licensed_sites = []
    site_details = []

    for site in sites:
        site_id = site.get("id", "")
        site_name = site.get("name", "")
        active_licenses = site.get("activeLicenses", 0) or 0
        total_licenses = site.get("totalLicenses", 0) or 0
        sku = site.get("sku", "") or ""
        state = site.get("state", "") or ""
        expiration = site.get("expiration", None)

        has_active_license = active_licenses > 0 and sku != ""
        if has_active_license:
            licensed_sites.append(site_name)
            confirmed = True

        site_details.append({
            "siteId": site_id,
            "siteName": site_name,
            "activeLicenses": active_licenses,
            "totalLicenses": total_licenses,
            "sku": sku,
            "state": state,
            "expiration": expiration,
            "hasActiveLicense": has_active_license,
        })

    if total_sites == 0:
        validation_warnings.append(
            "No sites returned from the API; unable to confirm license status."
        )

    data_collection_status = "error" if data_collection_errors else "success"

    if validation_errors:
        validation_status = "error"
    elif validation_warnings:
        validation_status = "warning"
    else:
        validation_status = "skipped"

    return {
        "transformedResponse": {
            "confirmedLicensePurchased": confirmed,
            "totalSites": total_sites,
            "licensedSiteCount": len(licensed_sites),
            "licensedSiteNames": licensed_sites,
            "siteDetails": site_details,
        },
        "additionalInfo": {
            "dataCollection": {
                "status": data_collection_status,
                "errors": data_collection_errors,
            },
            "validation": {
                "status": validation_status,
                "errors": validation_errors,
                "warnings": validation_warnings,
            },
        },
    }
