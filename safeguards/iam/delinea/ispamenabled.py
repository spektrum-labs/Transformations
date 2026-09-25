# ispamenabled.py - Delinea Platform (vault broker API)
#
# Method: getVaults -> GET {serverUrl}/vaultbroker/api/vaults
# Docs:   https://docs.delinea.com/online-help/platform-api/secret-server-apis-from-platform.htm
#         (vaultbroker.publicapi.json VaultViews): {vaults: [{vaultId, name, type, isDefault, isActive, connection: {url}}]}
# Auth:   Delinea Platform OAuth2 client credentials (POST {serverUrl}/identity/api/oauth2/token/xpmplatform, scope
#         xpmheadless); the same bearer token is accepted by the tenant's Secret Server (docs.delinea.com
#         /online-help/platform-api/secret-server-apis-from-platform.htm).

import json


def transform(input):
    """
    isPAMEnabled = true when the Platform tenant has at least one ACTIVE vault with a connection URL, i.e. a live
    Secret Server vault governs privileged credentials. False when there is none, or on any error body.
    """
    key = "isPAMEnabled"

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
        data = unwrap(parse_input(input), "vaults")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        vaults = data.get("vaults")
        if not isinstance(vaults, list):
            return {key: False, "reason": "Response has no vaults list"}
        live = []
        for v in vaults:
            if not isinstance(v, dict) or v.get("isActive") is not True:
                continue
            conn = v.get("connection")
            if isinstance(conn, dict) and isinstance(conn.get("url"), str) and conn.get("url").strip():
                live.append(v)
        if len(live) == 0:
            return {key: False, "reason": "No active vault with a connection URL", "vaults": len(vaults)}
        return {key: True, "reason": str(len(live)) + " active vault(s)", "vaults": [str(v.get("name")) for v in live][:10]}
    except Exception as e:
        return {key: False, "error": str(e)}
