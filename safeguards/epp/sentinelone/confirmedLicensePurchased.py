"""
Transformation: confirmedLicensePurchased
Vendor: SentinelOne
Category: epp
Method: checkLicenseStatus

Reads the /web/api/v2.1/sites/{siteId} response — a single site object — and confirms
the customer has a paid, active, unexpired license with capacity. Trial and free
siteTypes are NOT considered a confirmed purchase.
"""
import json
from datetime import datetime, timezone


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
        "evaluatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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


def _looks_like_site(d):
    if not isinstance(d, dict):
        return False
    return any(k in d for k in ("totalLicenses", "siteType", "unlimitedLicenses", "registrationToken"))


def _resolve_site(data):
    """Resolve the site object from whatever shape Token-Service preprocessing produced."""
    if not isinstance(data, dict):
        return None, "Input data is not a dict — cannot locate site object."

    # Most common: Token-Service unwrapped down to the site dict directly.
    if _looks_like_site(data):
        return data, None

    # /sites list-endpoint shape: data has a `sites` array.
    sites = data.get("sites")
    if isinstance(sites, list):
        if len(sites) == 1:
            return sites[0], None
        if len(sites) == 0:
            return None, "GET /sites returned an empty list — the apiToken cannot see any sites."
        return None, (f"GET /sites returned {len(sites)} sites; the integration must filter to a "
                      "single site via /sites/{siteId} or by configuring siteId.")

    # Defensive: one more layer of nesting.
    inner = data.get("data")
    if _looks_like_site(inner):
        return inner, None

    return None, "Could not locate a site object in the API response."


def transform(input):
    data, validation = extract_input(input)
    site, resolve_err = _resolve_site(data)

    if site is None:
        return create_response(
            result={"confirmedLicensePurchased": False},
            validation=validation,
            fail_reasons=[resolve_err or "No site object available; license cannot be confirmed."],
            recommendations=[
                "Verify the integration's checkLicenseStatus method targets "
                "/web/api/v2.1/sites/{siteId} and that the configured siteId is correct."
            ],
            input_summary={"siteFound": False},
            metadata={
                "transformationId": "confirmedLicensePurchased",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    state = (site.get("state") or "").lower() if isinstance(site.get("state"), str) else ""
    site_type_raw = site.get("siteType") or ""
    site_type = site_type_raw.lower() if isinstance(site_type_raw, str) else ""
    unlimited_licenses = bool(site.get("unlimitedLicenses"))
    unlimited_expiration = bool(site.get("unlimitedExpiration"))
    total_licenses = site.get("totalLicenses")
    if not isinstance(total_licenses, (int, float)):
        total_licenses = 0
    active_licenses = site.get("activeLicenses")
    if not isinstance(active_licenses, (int, float)):
        active_licenses = 0
    expiration_str = site.get("expiration") or ""
    sku = site.get("sku") or ""
    site_name = site.get("name") or site.get("id") or "unknown"

    is_active = state == "active"
    is_paid = site_type == "paid"  # exclude "trial", "free", and missing
    has_capacity = unlimited_licenses or total_licenses > 0

    is_unexpired = unlimited_expiration
    if not is_unexpired and isinstance(expiration_str, str) and expiration_str:
        try:
            exp_dt = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
            is_unexpired = exp_dt > datetime.now(timezone.utc)
        except Exception:
            is_unexpired = False

    confirmed = is_active and is_paid and has_capacity and is_unexpired

    extras = {
        "siteName": site_name,
        "siteState": state,
        "siteType": site_type_raw,
        "sku": sku,
        "totalLicenses": total_licenses,
        "activeLicenses": active_licenses,
        "unlimitedLicenses": unlimited_licenses,
        "expiration": expiration_str,
        "unlimitedExpiration": unlimited_expiration,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        capacity_str = "unlimited" if unlimited_licenses else f"{int(total_licenses)} licenses"
        expiry_str = "no expiration" if unlimited_expiration else f"expiring {expiration_str}"
        pass_reasons.append(
            f"Site '{site_name}' has siteType='{site_type_raw}' and state='active' with a valid "
            f"license entitlement ({capacity_str}, {expiry_str}, SKU '{sku}')."
        )
    else:
        if not is_active:
            fail_reasons.append(f"Site state is '{state or 'missing'}', not 'active'.")
            recommendations.append("Activate the site in the SentinelOne management console.")
        if not is_paid:
            actual = site_type_raw or "missing"
            fail_reasons.append(
                f"Site siteType is '{actual}', not 'Paid'. Trial and free sites are not considered "
                "a confirmed license purchase."
            )
            recommendations.append(
                "Convert this site to a paid subscription, or verify the customer has a purchased license."
            )
        if not has_capacity:
            fail_reasons.append(
                f"Site has no license capacity (totalLicenses={int(total_licenses)}, "
                f"unlimitedLicenses={unlimited_licenses})."
            )
            recommendations.append("Assign at least one Endpoint Security license to this site.")
        if not is_unexpired:
            if expiration_str:
                fail_reasons.append(
                    f"Site license expired or expiration unparseable (expiration='{expiration_str}', "
                    f"unlimitedExpiration={unlimited_expiration})."
                )
            else:
                fail_reasons.append(
                    f"Site license expiration is unknown (no `expiration` field and "
                    f"unlimitedExpiration={unlimited_expiration})."
                )
            recommendations.append("Renew the SentinelOne license before the expiration date.")

    return create_response(
        result={"confirmedLicensePurchased": confirmed, **extras},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"confirmedLicensePurchased": confirmed, **extras},
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
