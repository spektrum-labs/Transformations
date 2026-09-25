# isprivilegedidentitymanagementenabled.py - Delinea Secret Server (REST API v1)
#
# Method: getHeartbeatOverview -> GET {secretServerUrl}/api/v1/remote-password-changing/heartbeat-status-overview
# Docs:   Secret Server REST API reference 12.1.2 (updates.thycotic.net/secretserver/restapiguide/TokenAuth/),
#         HeartbeatStatusModel: {statuses: [{heartbeatStatus, total}], failedHeartbeatReportId, ...}
# Auth:   Delinea Platform OAuth2 client credentials (POST {serverUrl}/identity/api/oauth2/token/xpmplatform, scope
#         xpmheadless); the same bearer token is accepted by the tenant's Secret Server (docs.delinea.com
#         /online-help/platform-api/secret-server-apis-from-platform.htm).

import json


def transform(input):
    """
    isPrivilegedIdentityManagementEnabled = true when Secret Server actively verifies stored privileged accounts:
    at least one secret has heartbeat status Success (the account was checked against its target). False when
    every secret is Disabled/Pending/failing, when there are no secrets, or on any error body.
    Ruling needed: the line is "at least one"; coverage is reported, not judged.
    """
    key = "isPrivilegedIdentityManagementEnabled"

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
        data = unwrap(parse_input(input), "statuses")
        problem = vendor_error(data)
        if problem:
            return {key: False, "reason": problem}
        statuses = data.get("statuses")
        if not isinstance(statuses, list):
            return {key: False, "reason": "Response has no statuses list"}
        totals = {}
        for s in statuses:
            if not isinstance(s, dict):
                continue
            n = s.get("total")
            if isinstance(n, bool) or not isinstance(n, int):
                return {key: False, "reason": "A heartbeat status total is not a number"}
            name = str(s.get("heartbeatStatus"))
            totals[name] = totals.get(name, 0) + n
        success = 0
        for name in totals:
            if name.lower() == "success":
                success = success + totals[name]
        overall = sum([totals[n] for n in totals])
        if success == 0:
            return {key: False, "reason": "No secret has a successful heartbeat", "heartbeat": totals}
        return {key: True, "reason": str(success) + " of " + str(overall) + " secrets have a successful heartbeat", "heartbeat": totals}
    except Exception as e:
        return {key: False, "error": str(e)}
