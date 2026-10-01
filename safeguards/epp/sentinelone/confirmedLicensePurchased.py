"""
Transformation: confirmedLicensePurchased
Vendor: SentinelOne
Category: epp
Method: checkLicenseStatus

Reads GET /web/api/v2.1/sites?siteIds=<id> or ?accountIds=<id> (the list shape, every site in the
configured scope, paged by IS on pagination.nextCursor) or the older GET /sites/{siteId} (one site object),
and confirms every site in scope has a paid, active, unexpired license with capacity. Trial and free
siteTypes are NOT considered a confirmed purchase.

Fail closed: no site in the response, a vendor or IS error, or a partial list (fewer sites than
pagination.totalItems, a nextCursor left, or the IS `truncated` marker) returns None with a
dataCollection error. A list of several sites passes only when every site is confirmed.
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


def looks_like_site(d):
    if not isinstance(d, dict):
        return False
    return any(k in d for k in ("totalLicenses", "siteType", "unlimitedLicenses", "registrationToken"))


def resolve_sites(obj):
    """(sites, None) from whatever shape Token-Service hands over, or (None, problem)."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, "The site response is not JSON."
        if not isinstance(cur, dict):
            return None, "Could not locate a site object in the API response."
        if cur.get("errors") or cur.get("error") is True:
            detail = cur.get("errors") or cur.get("message") or cur.get("errorMessage") or "error"
            return None, "SentinelOne returned an error instead of site data: " + json.dumps(detail)[:300]
        if looks_like_site(cur):
            return [cur], None
        inner = cur.get("data")
        if isinstance(inner, dict) and isinstance(inner.get("sites"), list):
            pagination = cur.get("pagination")
            return check_complete([s for s in inner["sites"] if isinstance(s, dict)], pagination)
        if isinstance(cur.get("sites"), list):
            return check_complete([s for s in cur["sites"] if isinstance(s, dict)], None)
        nxt = None
        for key in ["result", "response", "apiResponse", "api_response", "Output", "data"]:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, "Could not locate a site object in the API response."
        cur = nxt
    return None, "Could not locate a site object in the API response."


def check_complete(sites, pagination):
    if not sites:
        return None, "GET /sites returned no site in the configured scope; the licence cannot be confirmed."
    if isinstance(pagination, dict):
        total = pagination.get("totalItems")
        if pagination.get("truncated"):
            return None, "The site list stopped at the page limit; a partial read is not scored."
        if str(pagination.get("nextCursor") or "").strip() not in ("", "None", "null"):
            return None, ("Only the first page of sites was read (" + str(len(sites)) + " of " + str(total)
                          + "); a partial read is not scored.")
        if isinstance(total, int) and not isinstance(total, bool) and len(sites) < total:
            return None, "Read " + str(len(sites)) + " of " + str(total) + " sites; a partial read is not scored."
    return sites, None


def judge_site(site):
    """(confirmed, extras, fail_reasons, recommendations) for one site object."""
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
    fail_reasons = []
    recommendations = []
    label = "Site '" + str(site_name) + "'"
    if not confirmed:
        if not is_active:
            fail_reasons.append(label + " state is '" + (state or "missing") + "', not 'active'.")
            recommendations.append("Activate the site in the SentinelOne management console.")
        if not is_paid:
            fail_reasons.append(label + " siteType is '" + str(site_type_raw or "missing") + "', not 'Paid'. Trial "
                                "and free sites are not considered a confirmed license purchase.")
            recommendations.append("Convert this site to a paid subscription, or verify the customer has a purchased license.")
        if not has_capacity:
            fail_reasons.append(label + " has no license capacity (totalLicenses=" + str(int(total_licenses))
                                + ", unlimitedLicenses=" + str(unlimited_licenses) + ").")
            recommendations.append("Assign at least one Endpoint Security license to this site.")
        if not is_unexpired:
            if expiration_str:
                fail_reasons.append(label + " license expired or expiration unparseable (expiration='"
                                    + str(expiration_str) + "', unlimitedExpiration=" + str(unlimited_expiration) + ").")
            else:
                fail_reasons.append(label + " license expiration is unknown (no `expiration` field and "
                                    "unlimitedExpiration=" + str(unlimited_expiration) + ").")
            recommendations.append("Renew the SentinelOne license before the expiration date.")
    return confirmed, extras, fail_reasons, recommendations


def transform(input):
    data, validation = extract_input(input)
    # Read the undrilled response (input.get("data") makes Token-Service pass it whole), so the
    # site list's pagination block is visible and a partial list returns None.
    raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
    metadata = {"transformationId": "confirmedLicensePurchased", "vendor": "SentinelOne", "category": "epp"}
    sites, problem = resolve_sites(raw)
    if problem is not None:
        return create_response(
            result={"confirmedLicensePurchased": None},
            validation=validation,
            fail_reasons=[problem],
            api_errors=[problem],
            recommendations=[
                "Verify the configured Site ID (or Account ID for account-wide scope) and that the API token can read it."
            ],
            input_summary={"siteFound": False},
            metadata=metadata,
        )

    judged = [judge_site(s) for s in sites]
    confirmed = all(j[0] for j in judged)
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    for ok, extras, fails, recs in judged:
        fail_reasons.extend(fails)
        for r in recs:
            if r not in recommendations:
                recommendations.append(r)
    if len(judged) == 1:
        extras = judged[0][1]
    else:
        extras = {
            "siteName": str(len(judged)) + " sites",
            "sitesTotal": len(judged),
            "sitesConfirmed": len([j for j in judged if j[0]]),
            "sites": [j[1] for j in judged],
        }
    if confirmed:
        for ok, e, fails, recs in judged:
            capacity_str = "unlimited" if e["unlimitedLicenses"] else str(int(e["totalLicenses"])) + " licenses"
            expiry_str = "no expiration" if e["unlimitedExpiration"] else "expiring " + str(e["expiration"])
            pass_reasons.append(
                "Site '" + str(e["siteName"]) + "' has siteType='" + str(e["siteType"]) + "' and state='active' with a "
                "valid license entitlement (" + capacity_str + ", " + expiry_str + ", SKU '" + str(e["sku"]) + "')."
            )

    return create_response(
        result={"confirmedLicensePurchased": confirmed, **extras},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"confirmedLicensePurchased": confirmed, **extras},
        metadata=metadata,
    )
