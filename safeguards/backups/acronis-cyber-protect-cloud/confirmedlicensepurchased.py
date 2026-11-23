"""Transformation: confirmedLicensePurchased - Acronis Cyber Protect Cloud (Account Management API v2).
Source: workflow getLicenseEvidence, three reads with the connection's API client token:
  "client"        GET /api/2/clients/{client_id}               (the API client; its tenant_id)
  "tenant"        GET /api/2/tenants/{tenant_id}               (enabled, pricing_mode)
  "offeringItems" GET /api/2/tenants/{tenant_id}/offering_items (items: application_id, status, edition)
True when the API client's tenant is enabled, its pricing mode is "production" (paid, not trial) and at
least one Cyber Protection offering item (application_id 6e6d758d-8e74-3ae3-ac84-50eb0dff12eb, the Cyber
Protection application in Acronis's own platform samples) is turned on (status 1).
False when the tenant is disabled, in trial or suspended pricing mode, or no Cyber Protection offering
item is turned on in a complete read.
Returns None (not measured) on anything else: empty or non-JSON bodies (the console's HTML login page), an
error envelope, a tenant that is not the API client's own, a pricing mode or status it does not know, or a
partial offering-item list or an unreadable item status with nothing turned on."""
import json
from datetime import datetime, timezone

KEY = "confirmedLicensePurchased"
METHOD = "getLicenseEvidence"

VENDOR = "Acronis"
PRODUCT = "Acronis Cyber Protect Cloud"
WRAPPERS = ["apiResponse", "api_response", "response", "result", "Output", "_response_data"]
CYBER_PROTECTION_APP = "6e6d758d-8e74-3ae3-ac84-50eb0dff12eb"
PAID_MODE = "production"
UNPAID_MODES = ["trial", "suspended"]


def to_obj(raw):
    """A parsed JSON value, or None for an empty or unparseable body."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except Exception:
            return None
    if isinstance(raw, str):
        text = raw.strip()
        if text == "":
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    return raw


def envelope_error(obj):
    """A short reason when obj is an Integration-Service or Acronis error envelope, else None.
    Fixed reasons: the vendor's own error text is never echoed into the result."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        return "The Acronis call did not return data"
    code = obj.get("status_code") or obj.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "The Acronis call returned HTTP " + str(code)
    if obj.get("status") == "Error":
        return "The Acronis call did not return data"
    return None


def step_into(cur):
    """The next level of wrapping (Token-Service data/validation or an IS wrapper), or None."""
    if "validation" in cur and "data" in cur:
        return to_obj(cur.get("data"))
    for w in WRAPPERS:
        if isinstance(cur.get(w), (dict, str, bytes)):
            return to_obj(cur.get(w))
    return None


def workflow_part(raw, key):
    """(the named part of the merged workflow body, None) or (None, reason)."""
    cur = to_obj(raw)
    for depth in range(8):
        if cur is None:
            return None, "The response body is empty or not JSON"
        if not isinstance(cur, dict):
            return None, "The response is not a JSON object"
        problem = envelope_error(cur)
        if problem is not None:
            return None, problem
        if key in cur:
            part = to_obj(cur.get(key))
            if not isinstance(part, dict):
                return None, "The " + key + " read is not a JSON object"
            problem = envelope_error(part)
            if problem is not None:
                return None, key + ": " + problem
            return part, None
        nxt = step_into(cur)
        if nxt is None:
            return None, "No " + key + " read in the response; nothing to evaluate"
        cur = nxt
    return None, "No " + key + " read found within 8 levels of wrapping"


HEX = "0123456789abcdef"


def is_uid(value):
    """True for a UUID: 36 characters, hex in 8-4-4-4-12 groups."""
    if not isinstance(value, str) or len(value) != 36:
        return False
    low = value.lower()
    for i in range(36):
        if i in (8, 13, 18, 23):
            if low[i] != "-":
                return False
        elif low[i] not in HEX:
            return False
    return True


def lower_text(value):
    return value.strip().lower() if isinstance(value, str) else None


def respond(key, method, value, reason, extra=None):
    """2.0 response. value None = not measured: dataCollection.status error, no verdict."""
    result = {key: value}
    if extra:
        for k in extra:
            result[k] = extra[k]
    measured = value is not None
    passed = value is True
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [],
                           "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": VENDOR, "product": PRODUCT, "method": method,
                         "evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0"},
        },
    }


def more_pages(coll):
    """True when the collection says pages remain unread (an Acronis paging cursor, or an IS truncation mark)."""
    paging = coll.get("paging")
    if not isinstance(paging, dict):
        return False
    cursors = paging.get("cursors")
    if not isinstance(cursors, dict):
        return False
    if cursors.get("truncated") is True:
        return True
    after = cursors.get("after")
    return isinstance(after, str) and after.strip() != ""


def evaluate(input):
    client, why = workflow_part(input, "client")
    if why:
        return respond(KEY, METHOD, None, why)
    tenant_id = lower_text(client.get("tenant_id"))
    if not is_uid(tenant_id):
        return respond(KEY, METHOD, None, "The API client record carries no tenant_id, so its tenant cannot be read")

    tenant, why = workflow_part(input, "tenant")
    if why:
        return respond(KEY, METHOD, None, why)
    if lower_text(tenant.get("id")) != tenant_id:
        return respond(KEY, METHOD, None, "The tenant read is not the API client's own tenant")
    enabled = tenant.get("enabled")
    mode = lower_text(tenant.get("pricing_mode"))
    extra = {"pricingMode": mode, "tenantEnabled": enabled if isinstance(enabled, bool) else None,
             "tenantKind": lower_text(tenant.get("kind"))}
    if enabled is False:
        return respond(KEY, METHOD, False, "The API client's Acronis tenant is disabled", extra)
    if mode in UNPAID_MODES:
        return respond(KEY, METHOD, False, "The API client's Acronis tenant is in " + mode +
                       " pricing mode, not a paid (production) subscription", extra)
    if enabled is not True:
        return respond(KEY, METHOD, None, "The tenant read does not say whether the tenant is enabled")
    if mode != PAID_MODE:
        return respond(KEY, METHOD, None, "The tenant read carries no pricing mode Spektrum knows "
                       "(production, trial or suspended)")

    coll, why = workflow_part(input, "offeringItems")
    if why:
        return respond(KEY, METHOD, None, why)
    items = coll.get("items")
    if not isinstance(items, list):
        return respond(KEY, METHOD, None, "The offering-item read carries no items list")
    on = []
    protection = 0
    unread = 0
    for it in items:
        if not isinstance(it, dict):
            return respond(KEY, METHOD, None, "An offering item is not an object")
        if lower_text(it.get("application_id")) != CYBER_PROTECTION_APP:
            continue
        owner = lower_text(it.get("tenant_id"))
        if owner and owner != tenant_id:
            continue
        protection = protection + 1
        status = it.get("status")
        if isinstance(status, bool) or not isinstance(status, int) or status not in (0, 1):
            unread = unread + 1
        elif status == 1:
            on.append(it)
    extra["protectionOfferingItems"] = protection
    extra["protectionOfferingItemsOn"] = len(on)
    extra["editions"] = sorted(set([str(x.get("edition")) for x in on if x.get("edition")]))[:10]
    if len(on) > 0:
        return respond(KEY, METHOD, True, "The tenant is on a paid (production) subscription with " + str(len(on)) +
                       " Cyber Protection offering item(s) turned on", extra)
    if unread > 0:
        return respond(KEY, METHOD, None, str(unread) + " Cyber Protection offering items report a status Spektrum "
                       "cannot read (expected 1 = on or 0 = off)")
    if more_pages(coll):
        return respond(KEY, METHOD, None, "Only part of the offering-item list was read and no Cyber Protection "
                       "item is turned on in it, so the licence cannot be shown either way")
    if protection == 0:
        return respond(KEY, METHOD, False, "No Cyber Protection offering item is assigned to the tenant", extra)
    return respond(KEY, METHOD, False, "None of the tenant's " + str(protection) +
                   " Cyber Protection offering items is turned on", extra)


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled response as {"data": <response>, "validation": ...}, so the three named reads stay intact.
    try:
        if isinstance(input, dict) and "validation" in input and not isinstance(input.get("data"), list):
            input = input.get("data")
        return evaluate(input)
    except Exception as e:
        return respond(KEY, METHOD, None, "Transformation error: " + str(e)[:300])
