"""
Transformation: confirmedLicensePurchased
Vendor: Sophos  |  Category: Firewall

Per-product licence for Sophos Firewall (5 Oct 2026). The shared Sophos licence file reads the account health check,
which does not say which product is licensed (TX #921), so Firewall read Not evaluated.

Inputs (any of):
- the per-firewall licence list, GET https://api.central.sophos.com/licenses/v1/licenses/firewalls
  ({"items": [{"serialNumber", "model", "licenses": [licence items]}], "pages": {...}}), bare or merged under
  "firewallLicenses";
- the tenant licence list, GET https://api.central.sophos.com/licenses/v1/licenses ({"licenses": [...]}), bare or
  merged under "tenantLicenses". Firewall subscriptions are held per device, so the tenant list usually carries none.

Per licence item: a trial never counts; an item counts as active when it has started and is perpetual or ends today or
later. Dates are compared as YYYY-MM-DD strings.

- True: the per-firewall list was read whole, lists at least one firewall, and every firewall carries an active
  licence; or the tenant list carries an active firewall product (product name containing "Firewall" or "Xstream").
- False: the per-firewall list was read whole and a firewall's licences are all expired or trial.
- Not evaluated (None, dataCollection error): an error body, a list not read whole (pages.total above the items
  read), no firewall listed, a firewall listed with no licence items or unreadable dates, or only the tenant list
  with no firewall product in it (it cannot show a per-device subscription, so it is never a fail).
"""
import json
from datetime import datetime

CRITERIA_KEY = "confirmedLicensePurchased"


def extract_input(input_data):
    if isinstance(input_data, (str, bytes)):
        input_data = json.loads(input_data.decode("utf-8") if isinstance(input_data, bytes) else input_data)
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    for _ in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), dict):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation, passed=(), failed=(), errors=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {"passReasons": list(passed), "failReasons": list(failed) + list(errors),
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORMATION_ID, "vendor": "Sophos", "category": CATEGORY},
        },
    }


def not_evaluated(reason, validation, summary=None):
    return create_response({CRITERIA_KEY: None}, validation, errors=[reason], summary=summary)


def day(value):
    """'YYYY-MM-DD' from an ISO date or timestamp string; '' when it is not one."""
    text = str(value or "").strip()[:10]
    if len(text) == 10 and text[4] == "-" and text[7] == "-" and (text[:4] + text[5:7] + text[8:]).isdigit():
        return text
    return ""


def licence_state(lic, today):
    """'active', 'expired', 'trial', 'future' or 'unknown' for one Sophos licence item."""
    if not isinstance(lic, dict):
        return "unknown"
    if str(lic.get("type") or "").strip().lower() == "trial":
        return "trial"
    start = day(lic.get("startDate"))
    if start and start > today:
        return "future"
    if lic.get("perpetual") is True:
        return "active"
    end = day(lic.get("endDate"))
    if not end:
        return "unknown"
    return "active" if end >= today else "expired"


def product_of(lic):
    product = lic.get("product") if isinstance(lic, dict) else None
    product = product if isinstance(product, dict) else {}
    return str(product.get("code") or "").strip(), str(product.get("name") or "").strip()

TRANSFORMATION_ID = "sophosFirewallConfirmedLicensePurchased"
CATEGORY = "Firewall"
PRODUCT_LABEL = "Sophos Firewall"


def is_firewall_product(code, name):
    text = (code + " " + name).lower()
    return "firewall" in text or "xstream" in text


def bad_body(body):
    return not isinstance(body, dict) or "error" in body or "vendorErrorAsResponse" in body


def judge_devices(body, validation, today):
    items = body.get("items")
    if not isinstance(items, list):
        return not_evaluated("The Sophos firewall licence response carries no items array", validation)
    pages = body.get("pages") if isinstance(body.get("pages"), dict) else {}
    total = pages.get("items")
    if isinstance(total, int) and not isinstance(total, bool) and total > len(items):
        return not_evaluated(f"The Sophos firewall licence list was not read whole ({len(items)} of {total})",
                             validation)
    if not items:
        return not_evaluated("Sophos lists no firewall licences, so there is nothing to measure", validation)
    good = 0
    lapsed = 0
    unclear = 0
    for device in items:
        licences = device.get("licenses") if isinstance(device, dict) else None
        if not isinstance(licences, list) or not licences:
            unclear = unclear + 1
            continue
        states = [licence_state(lic, today) for lic in licences]
        if "active" in states:
            good = good + 1
        elif "unknown" in states:
            unclear = unclear + 1
        else:
            lapsed = lapsed + 1
    summary = {"firewalls": len(items), "licensed": good, "lapsed": lapsed, "unclear": unclear}
    result = {CRITERIA_KEY: None, "product": PRODUCT_LABEL, "firewalls": len(items), "firewallsLicensed": good}
    if lapsed:
        result[CRITERIA_KEY] = False
        return create_response(result, validation, failed=[
            f"{lapsed} of {len(items)} Sophos firewall(s) carry only expired or trial licences"], summary=summary)
    if unclear:
        return not_evaluated(f"{unclear} of {len(items)} Sophos firewall(s) list no licence with readable dates",
                             validation, summary=summary)
    result[CRITERIA_KEY] = True
    return create_response(result, validation, passed=[
        f"All {len(items)} Sophos firewall(s) carry a current licence"], summary=summary)


def judge_tenant(body, validation, today):
    licences = body.get("licenses")
    if not isinstance(licences, list):
        return not_evaluated("The Sophos response carries no licenses array", validation)
    active = []
    for lic in licences:
        code, name = product_of(lic)
        if is_firewall_product(code, name) and licence_state(lic, today) == "active":
            active.append(code or name[:40])
    result = {CRITERIA_KEY: None, "product": PRODUCT_LABEL, "productLicences": len(active)}
    summary = {"licencesRead": len(licences), "activeFirewallProducts": len(active)}
    if active:
        result[CRITERIA_KEY] = True
        return create_response(result, validation, passed=[
            f"{PRODUCT_LABEL} licence is current in the tenant licence list (product "
            f"{', '.join(sorted(set(active)))[:80]})"], summary=summary)
    return not_evaluated("The Sophos tenant licence list (" + str(len(licences)) + " item(s)) carries no firewall "
                         "product; firewall subscriptions are held per device and read from "
                         "/licenses/v1/licenses/firewalls", validation, summary=summary)


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_evaluated("Input validation failed: the Sophos licence lists were not read", validation)
        if bad_body(data):
            return not_evaluated("Sophos did not return a licence list (error or unrecognised body)", validation)
        today = datetime.utcnow().date().isoformat()
        devices = data.get("firewallLicenses") if "firewallLicenses" in data else (data if "items" in data else None)
        tenant = data.get("tenantLicenses") if "tenantLicenses" in data else (data if "licenses" in data else None)
        if devices is not None and not bad_body(devices):
            return judge_devices(devices, validation, today)
        if tenant is not None and not bad_body(tenant):
            return judge_tenant(tenant, validation, today)
        return not_evaluated("Sophos returned no readable firewall or tenant licence list", validation)
    except Exception as e:
        return not_evaluated("Transformation error: " + str(e)[:200], {"status": "error", "errors": [], "warnings": []})
