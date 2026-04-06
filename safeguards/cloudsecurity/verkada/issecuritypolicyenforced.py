import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Verkada

    Checks: Whether Verkada access control levels are configured
    API Source: {baseURL}/access/v1/access_levels
    Pass Condition: At least one access level is configured and active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activePolicies": int, "totalPolicies": int}
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
        levels = data.get("access_levels", data.get("data", data.get("results", data.get("items", []))))

        if not isinstance(levels, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activePolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected access levels response format"
            }

        total = len(levels)
        active = []
        for level in levels:
            enabled = level.get("enabled", level.get("active", level.get("status", "")))
            levelName = level.get("name", level.get("access_level_name", ""))
            if enabled is True:
                active.append(level)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(level)
            elif levelName and enabled is not False:
                active.append(level)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
