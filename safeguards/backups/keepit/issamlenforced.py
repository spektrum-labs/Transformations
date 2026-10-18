# issamlenforced.py - Keepit
#
# Method: getSSOConfig -> GET {serverUrl}/users/{accountId}/ssoconfig
# Docs:   https://developers.keepit.com/api/accounts/sso#get-sso-configuration
#         schema "sso-configurations" (https://developers.keepit.com/api/accounts/~schemas#sso-configurations)
#
# Keepit SSO is configured from an IdP URL plus the IdP's Base64 certificate; the Keepit help
# center's Entra ID guide takes that URL from the "SAML Single Sign-On Service URL" field.
# The body arrives as {"configurations": {"configuration": {...} | [{...}, ...]}}, or
# {"configurations": None} when SSO is not configured.

import json
from datetime import datetime, timezone

KEY = "isSAMLEnforced"
METHOD = "getSSOConfig"


def transform_bare(input):
    """
    True when at least one Keepit SSO configuration is enabled, is not optional
    (<optional>false</optional>, so users cannot fall back to a password), and applies both to
    the account itself and to its sub-accounts (<apply_self>true</apply_self> and
    <apply_subaccounts>true</apply_subaccounts>). Keepit users created under Users are
    sub-accounts, so a configuration that skips them does not enforce SSO on them.

    Proves: Keepit requires IdP (SAML) sign-in for the account and its users.
    Does not prove: the state of any per-user break-glass exemption, or MFA at the IdP.
    An empty <configurations/> (SSO not configured) answers false; a body without
    <configurations>, or one that cannot be read, answers None.
    """
    key = "isSAMLEnforced"

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
        enforcing = []
        gaps = []
        for c in configs:
            name = str(c.get("name") or c.get("prefix") or c.get("guid") or "")
            missing = []
            if as_bool(c.get("enabled")) is not True:
                missing.append("not enabled")
            if as_bool(c.get("optional")) is not False:
                missing.append("optional (password login still allowed)")
            if as_bool(c.get("apply_self")) is not True:
                missing.append("not applied to the account")
            if as_bool(c.get("apply_subaccounts")) is not True:
                missing.append("not applied to sub-accounts")
            if len(missing) == 0:
                enforcing.append(name)
            else:
                gaps.append(name + ": " + ", ".join(missing))

        result = len(enforcing) > 0
        if result:
            reason = "SSO configuration " + enforcing[0] + " is enabled, mandatory and applies to the account and its sub-accounts"
        elif len(configs) == 0:
            reason = "SSO is not configured on the account"
        else:
            reason = "No SSO configuration is enforced: " + "; ".join(gaps)
        return {
            key: result,
            "reason": reason,
            "ssoConfigurationCount": len(configs),
            "enforcingConfigurations": enforcing,
            "configurationGaps": gaps,
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
