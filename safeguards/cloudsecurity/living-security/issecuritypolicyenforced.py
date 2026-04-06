import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Living Security

    Checks: Whether security awareness playbooks are configured and active
    API Source: {baseURL}/api/v1/playbooks
    Pass Condition: At least 1 active playbook or intervention exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activePlaybooks": int, "totalPlaybooks": int}
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

        # -- EVALUATION LOGIC --
        playbooks = data.get("playbooks", data.get("data", data.get("results", data.get("items", []))))

        if not isinstance(playbooks, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activePlaybooks": 0,
                "totalPlaybooks": 0,
                "error": "Unexpected playbooks response format"
            }

        total = len(playbooks)

        active = [
            p for p in playbooks
            if p.get("enabled", False) is True
            or p.get("active", False) is True
            or str(p.get("status", "")).lower() in ("active", "enabled", "running")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePlaybooks": len(active),
            "totalPlaybooks": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
