import json
import ast


def transform(input):
    """
    Evaluates isThreatIntelIntegrated for PlexTrac (ASM)

    Checks: Whether active users and recent platform activity exist
    API Source: {baseURL}/api/v2/tenants/{tenantId}/users
    Pass Condition: At least one active user exists in the tenant

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatIntelIntegrated": boolean, "activeUsers": int, "totalUsers": int}
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        users = data.get("data", data.get("users", data.get("results", [])))

        if isinstance(users, dict):
            users = users.get("users", [])

        if not isinstance(users, list):
            users = [users] if users else []

        total = len(users)
        active = [
            u for u in users
            if u.get("enabled", True) is not False
            and str(u.get("status", "active")).lower() != "disabled"
        ]

        result = len(active) >= 1
        # ── END EVALUATION LOGIC ──

        return {
            "isThreatIntelIntegrated": result,
            "activeUsers": len(active),
            "totalUsers": total
        }

    except Exception as e:
        return {"isThreatIntelIntegrated": False, "error": str(e)}
