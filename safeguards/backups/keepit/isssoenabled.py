# isssoenabled.py - Keepit
#
# Method: getSSOConfig -> GET {serverUrl}/users/{accountId}/ssoconfig
# Docs:   https://developers.keepit.com/api/accounts/sso#get-sso-configuration
#         schema "sso-configurations" (https://developers.keepit.com/api/accounts/~schemas#sso-configurations)
#
# Keepit answers in XML only; Integration-Service parses it with xmltodict, so the body arrives
# as {"configurations": {"configuration": {...} | [{...}, ...]}}. When SSO is not configured
# Keepit returns an empty <configurations/>, which parses to {"configurations": None}.

import json
from datetime import datetime, timezone

KEY = "isSSOEnabled"
METHOD = "getSSOConfig"


def transform_bare(input):
    """
    True when at least one Keepit SSO configuration is enabled (<enabled>true</enabled>) and
    applies to the account's own logins or to its sub-accounts (<apply_self>true</apply_self>
    or <apply_subaccounts>true</apply_subaccounts>).

    Proves: Keepit sign-in is federated to an identity provider for this account.
    Does not prove: that password login is switched off (see isSAMLEnforced) or that the
    identity provider enforces MFA. An empty <configurations/> (SSO not configured) answers
    false; a body without <configurations>, or one that cannot be read, answers None.
    """
    key = "isSSOEnabled"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("raw XML body was not parsed by Integration-Service")
            return json.loads(text)
        return value

    def listify(value):
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return value
        return [value]

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
            if isinstance(data, dict) and wrapper in data and "configurations" not in data:
                data = data[wrapper]

        if not isinstance(data, dict) or "configurations" not in data:
            return {key: None, "reason": "Response has no <configurations> element, so SSO could not be read"}

        block = data.get("configurations")
        if block is None or block == "":
            block = {}
        if not isinstance(block, dict):
            return {key: None, "reason": "<configurations> element has an unexpected shape"}

        configs = [c for c in listify(block.get("configuration")) if isinstance(c, dict)]
        active = []
        for c in configs:
            if as_bool(c.get("enabled")) is True and (as_bool(c.get("apply_self")) is True or as_bool(c.get("apply_subaccounts")) is True):
                active.append(str(c.get("name") or c.get("prefix") or c.get("guid") or ""))

        result = len(active) > 0
        if result:
            reason = str(len(active)) + " of " + str(len(configs)) + " SSO configurations are enabled and applied"
        elif len(configs) == 0:
            reason = "SSO is not configured on the account"
        else:
            reason = "No SSO configuration is both enabled and applied to the account or its sub-accounts"
        return {
            key: result,
            "reason": reason,
            "ssoConfigurationCount": len(configs),
            "activeSsoConfigurations": active,
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
