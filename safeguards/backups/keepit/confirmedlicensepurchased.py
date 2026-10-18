# confirmedlicensepurchased.py - Keepit
#
# Method: getAccount -> GET {serverUrl}/users/{accountId}   (API version 0, the default)
# Docs:   https://developers.keepit.com/api/accounts/accounts#get-account-details
#         schema "user-v0" (https://developers.keepit.com/api/accounts/~schemas#user-v0)
#
# Keepit answers in XML only; Integration-Service parses it with xmltodict, so the body arrives
# as {"user": {"enabled": "true", "created": "...", "product": "<guid>", "subscribed": "true"}}.

import json
from datetime import datetime, timezone

KEY = "confirmedLicensePurchased"
METHOD = "getAccount"


def transform_bare(input):
    """
    Returns confirmedLicensePurchased = "confirmed" when Keepit reports the account as
    enabled (<enabled>true</enabled>), subscribed (<subscribed>true</subscribed>), with a
    product assigned (<product> present) and not scheduled for deletion (no
    <deletion-deadline>). A readable <user> that fails any of these returns "unconfirmed".
    A body without <user>, or one that cannot be read, returns None (not measured). The
    requirement compares with isEquals "confirmed".

    Proves: Keepit itself says the account holds an active subscription with a product.
    Does not prove: which workloads the product licenses, seat counts, or the product's grace
    period (that is on the Products API and is not read here).
    """
    key = "confirmedLicensePurchased"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("raw XML body was not parsed by Integration-Service")
            return json.loads(text)
        return value

    def as_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low == "true":
                return True
            if low == "false":
                return False
        return None

    try:
        data = parse_input(input)
        for wrapper in ["response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data and "user" not in data:
                data = data[wrapper]

        if not isinstance(data, dict) or not isinstance(data.get("user"), dict):
            return {key: None, "reason": "Response has no <user> element, so the account could not be read"}

        user = data["user"]
        enabled = as_bool(user.get("enabled"))
        subscribed = as_bool(user.get("subscribed"))
        product = user.get("product")
        has_product = isinstance(product, str) and product.strip() != ""
        deletion = user.get("deletion-deadline")

        problems = []
        if enabled is not True:
            problems.append("account is not reported enabled")
        if subscribed is not True:
            problems.append("account is not reported subscribed")
        if not has_product:
            problems.append("no product is assigned")
        if deletion:
            problems.append("account is scheduled for deletion")

        confirmed = len(problems) == 0
        return {
            key: "confirmed" if confirmed else "unconfirmed",
            "reason": "Account is enabled, subscribed and has a product assigned" if confirmed else "; ".join(problems),
            "enabled": enabled,
            "subscribed": subscribed,
            "productAssigned": has_product,
        }
    except Exception as e:
        return {key: None, "error": str(e)}


def envelope(key, method, bare):
    """Wrap a bare result in the platform envelope.

    Whether the criterion was measured is read from its value alone: None means the body could
    not answer the check, so dataCollection reports an error and Token-Service does not grade
    it. Every other value, including a measured False, reports success.
    """
    value = bare.get(key)
    reason = str(bare.get("reason") or bare.get("error") or "The response could not answer this check")
    measured = value is not None
    passed = value is True or value == "confirmed"
    return {
        "transformedResponse": bare,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Keepit", "product": "Keepit", "method": method,
                         "evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0"},
        },
    }


def transform(input):
    """transform_bare() in the platform envelope; a None criterion reports a dataCollection error."""
    return envelope(KEY, METHOD, transform_bare(input))
