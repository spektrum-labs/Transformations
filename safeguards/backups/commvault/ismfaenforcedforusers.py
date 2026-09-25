# ismfaenforcedforusers.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getTwoFactorAuth -> GET {serverUrl}/Commcell/Properties/TwoFactorAuth (Accept: application/json)
# Docs:   Commvault's official Python SDK, cvpysdk/services.py 'TFA' and
#         cvpysdk/security/two_factor_authentication.py (https://github.com/Commvault/cvpysdk):
#         twoFactorAuthenticationInfo.mode 0 = disabled, 1 = all users, 2 = selected user groups (userGroups).
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    isMFAEnforcedForUsers = true when CommCell two-factor authentication mode is 1 (every user). Mode 2
    (selected user groups only) and 0 (off) are false, as is an unreadable or error body.
    """
    key = "isMFAEnforcedForUsers"

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
        data = unwrap(parse_input(input), "twoFactorAuthenticationInfo")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        info = data.get("twoFactorAuthenticationInfo")
        if not isinstance(info, dict) or "mode" not in info:
            return {key: False, "reason": "Response has no twoFactorAuthenticationInfo.mode"}
        mode = as_int(info.get("mode"))
        if mode == 1:
            return {key: True, "reason": "Two-factor authentication is enforced for all users"}
        if mode == 2:
            groups = [str(g.get("userGroupName")) for g in (info.get("userGroups") or []) if isinstance(g, dict)]
            return {key: False, "reason": "Two-factor authentication applies only to selected user groups", "userGroups": groups[:25]}
        return {key: False, "reason": "Two-factor authentication is off (mode " + str(info.get("mode")) + ")"}
    except Exception as e:
        return {key: False, "error": str(e)}
