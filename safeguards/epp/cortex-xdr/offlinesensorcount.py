# offlinesensorcount.py - Palo Alto Networks Cortex XDR (Endpoint Security, f1b50389)
#
# Method: getEndpointCounts (IS workflow). Each step POSTs {serverUrl}/public_api/v1/endpoints/get_endpoint
#         with one filter and stores the body under its output key:
#           enrolled  = endpoint_status in [connected, disconnected, lost]
#           connected = endpoint_status in [connected]
#           offline   = endpoint_status in [disconnected, lost]
#           isolated  = isolate in [isolated]
# Docs:   Cortex XDR REST API, Get Endpoint (docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Endpoint):
#           response reply.total_count / result_count / endpoints; endpoint_status CONNECTED, DISCONNECTED,
#           LOST, UNINSTALLED; is_isolated AGENT_ISOLATED / AGENT_PENDING_ISOLATION / AGENT_UNISOLATED.
#         The server counts (total_count), so no endpoint paging is needed.

import json


def transform(input):
    """
    Count of endpoints whose endpoint_status is DISCONNECTED or LOST. None when unreadable.
    """
    key = "offlineSensorCount"

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    def unwrap(value, marker):
        for depth in range(4):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(w), dict):
                    value = value[w]
                    moved = True
                    break
            if not moved:
                break
        return value

    def total(data, name):
        """reply.total_count of the get_endpoint call stored under <name>, or None."""
        body = unwrap(data.get(name), "reply") if isinstance(data, dict) else None
        reply = body.get("reply") if isinstance(body, dict) else None
        if not isinstance(reply, dict):
            return None
        n = reply.get("total_count")
        if isinstance(n, int) and not isinstance(n, bool) and n >= 0:
            return n
        return None

    try:
        data = unwrap(parse(input), "enrolled")
        if isinstance(data, dict) and (data.get("error") or str(data.get("status", "")).lower() == "error"):
            return {key: None, "reason": "Integration-Service returned an error envelope"}
        n = total(data, "offline")
        if n is None:
            return {key: None, "reason": "No readable total_count for disconnected/lost endpoints"}
        return {key: n}
    except Exception as e:
        return {key: None, "error": str(e)}
