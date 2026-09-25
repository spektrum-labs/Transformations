# isauditlogforwardingenabled.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getSyslogServer -> GET {serverUrl}/V4/syslogServer (Accept: application/json)
# Docs:   https://github.com/Commvault/CVPowershellSDKV2/blob/main/OpenAPI3.yaml (Commvault's published V4 OpenAPI 3 spec)
#         operation GetSyslogStatus: hostname, port, enabled, forwardToSyslog.audit ("Forward the system log for
#         audit trails to the server").
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    isAuditLogForwardingEnabled = true when syslog forwarding is enabled, has a hostname, and forwards the
    audit trail (forwardToSyslog.audit true). false otherwise, including an unreadable body.
    """
    key = "isAuditLogForwardingEnabled"

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
        data = unwrap(parse_input(input), "enabled")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        if "enabled" not in data:
            return {key: False, "reason": "Response has no syslog enabled flag"}
        fwd = data.get("forwardToSyslog") if isinstance(data.get("forwardToSyslog"), dict) else {}
        if data.get("enabled") is not True:
            return {key: False, "reason": "Syslog forwarding is disabled"}
        if not str(data.get("hostname") or "").strip():
            return {key: False, "reason": "Syslog forwarding has no hostname"}
        if fwd.get("audit") is not True:
            return {key: False, "reason": "Syslog is enabled but the audit trail is not forwarded"}
        return {key: True, "reason": "Audit trail is forwarded to syslog (TLS " + ("on" if data.get("secureMessaging") is True else "off") + ")"}
    except Exception as e:
        return {key: False, "error": str(e)}
