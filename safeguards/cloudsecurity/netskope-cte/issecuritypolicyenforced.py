import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Netskope Cloud Threat Exchange

    Checks: Whether CTE plugins are configured and active
    API Source: {baseURL}/api/cte/plugins
    Pass Condition: At least one active plugin configuration exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activePlugins": int, "totalPlugins": int}
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
        plugins = data.get("data", data.get("results", data.get("items", data.get("plugins", []))))

        if not isinstance(plugins, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activePlugins": 0,
                "totalPlugins": 0,
                "error": "Unexpected plugins response format"
            }

        total = len(plugins)
        active = [
            p for p in plugins
            if p.get("enabled", False) is True
            or str(p.get("enabled", "")).lower() in ("true", "1", "yes")
            or p.get("status", "").lower() in ("enabled", "active", "running")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePlugins": len(active),
            "totalPlugins": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
