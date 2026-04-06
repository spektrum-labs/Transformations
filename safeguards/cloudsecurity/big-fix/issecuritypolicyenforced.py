import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for HCL BigFix

    Checks: Whether fixlets (security policies/patches) are configured in the master action site
    API Source: {baseURL}/fixlets/master
    Pass Condition: At least one fixlet is configured and available for enforcement

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activeFixlets": int, "totalFixlets": int}
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
        fixlets = data.get("data", data.get("fixlets", data.get("results", data.get("items", []))))

        if not isinstance(fixlets, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activeFixlets": 0,
                "totalFixlets": 0,
                "error": "Unexpected fixlets response format"
            }

        total = len(fixlets)
        active = []
        for f in fixlets:
            enabled = f.get("enabled", f.get("active", f.get("status", "")))
            if enabled is True:
                active.append(f)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(f)

        activeCount = len(active) if active else total
        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activeFixlets": activeCount,
            "totalFixlets": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
