# isssoenabled.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getIdentityServers -> GET {serverUrl}/V4/IdentityServers (Accept: application/json)
# Docs:   https://github.com/Commvault/CVPowershellSDKV2/blob/main/OpenAPI3.yaml (Commvault's published V4 OpenAPI 3 spec)
#         operation GetIdentityServers: identityServers[].type (SAML, ACTIVE_DIRECTORY, ...), samlType, configured.
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    isSSOEnabled = true when at least one identity server of type SAML is present and not marked
    configured: false. false otherwise, including an unreadable body.
    """
    key = "isSSOEnabled"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("XML body; the method must send Accept: application/json")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        # Integration-Service may hand the body back under one of its envelopes.
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
        """A reason string when the body is an Integration-Service or Commvault error, else None.
        Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        code = d.get("errorCode")
        if code not in (None, 0, "0"):
            return "Commvault error " + str(code) + ": " + str(d.get("errorMessage") or "")
        errs = d.get("errList")
        if isinstance(errs, list) and len(errs) > 0:
            return "Commvault errList: " + str(errs[0])[:200]
        err = d.get("error")
        if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
            return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")
        return None

    def as_int(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        return None

    try:
        data = unwrap(parse_input(input), "identityServers")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        servers = data.get("identityServers")
        if not isinstance(servers, list):
            return {key: False, "reason": "Response has no identityServers list"}
        saml = [s for s in servers if isinstance(s, dict) and str(s.get("type") or "").upper() == "SAML" and s.get("configured") is not False]
        if len(saml) == 0:
            return {key: False, "reason": "No configured SAML identity server (" + str(len(servers)) + " identity servers read)"}
        return {key: True, "reason": str(len(saml)) + " SAML identity servers configured", "samlApps": [str(s.get("name")) + " (" + str(s.get("samlType")) + ")" for s in saml][:10]}
    except Exception as e:
        return {key: False, "error": str(e)}
