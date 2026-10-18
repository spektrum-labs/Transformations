# isssoenabled.py - Delinea Platform (identity-federation API)
#
# Method: getSAMLProviders -> GET {serverUrl}/identity-federation/api/saml-providers
# Docs:   https://docs.delinea.com/online-help/platform-api/identity-federation.htm
#         (identity-federation.externalapi.json): {records: [{id, entityId, enabled, loginUrl, ...}], count, totalCount}
# Auth:   Delinea Platform OAuth2 client credentials (POST {serverUrl}/identity/api/oauth2/token/xpmplatform, scope
#         xpmheadless); the same bearer token is accepted by the tenant's Secret Server (docs.delinea.com
#         /online-help/platform-api/secret-server-apis-from-platform.htm).

import json


def transform(input):
    """
    isSSOEnabled = true when the Platform tenant has at least one ENABLED SAML identity provider, so users sign in
    through an external IdP. False when none is enabled, when providers were left unread, or on any error body.
    """
    key = "isSSOEnabled"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("HTML or XML body; expected JSON from the Delinea API")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def vendor_error(d):
        """A reason when the body is an Integration-Service or Delinea error, else None."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        if d.get("success") is False:
            return "Delinea reported success=false: " + str(d.get("message") or d.get("Message") or "")[:200]
        if d.get("errorCode"):
            return "Delinea error " + str(d.get("errorCode")) + ": " + str(d.get("message") or "")[:200]
        status = d.get("status")
        if isinstance(status, int) and status >= 400:
            return "Delinea HTTP " + str(status) + ": " + str(d.get("title") or d.get("detail") or "")[:200]
        return None

    try:
        data = unwrap(parse_input(input), "records")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        records = data.get("records")
        if not isinstance(records, list):
            return {key: False, "reason": "Response has no records list"}
        enabled = [r for r in records if isinstance(r, dict) and r.get("enabled") is True]
        if len(enabled) > 0:
            return {key: True, "reason": str(len(enabled)) + " enabled SAML identity provider(s)",
                    "providers": [str(r.get("entityId") or r.get("id")) for r in enabled][:25]}
        total = data.get("totalCount")
        if isinstance(total, int) and total > len(records):
            return {key: False, "reason": "Only " + str(len(records)) + " of " + str(total) + " SAML providers were read"}
        return {key: False, "reason": "No enabled SAML identity provider", "providers": len(records)}
    except Exception as e:
        return {key: False, "error": str(e)}
