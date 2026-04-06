import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Asset Panda

    Checks: Whether asset management actions and rules are configured
    API Source: {baseURL}/v3/entities/actions
    Pass Condition: At least one action or rule is configured for asset management

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activeActions": int, "totalActions": int}
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
        actions = data.get("data", data.get("actions", data.get("results", data.get("items", []))))

        if not isinstance(actions, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activeActions": 0,
                "totalActions": 0,
                "error": "Unexpected actions response format"
            }

        total = len(actions)
        active = []
        for a in actions:
            enabled = a.get("enabled", a.get("active", a.get("status", "")))
            if enabled is True:
                active.append(a)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(a)

        activeCount = len(active) if active else total
        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activeActions": activeCount,
            "totalActions": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
