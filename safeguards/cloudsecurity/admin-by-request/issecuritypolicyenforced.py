import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Admin By Request

    Checks: Whether privileged access policies are configured and enforced
    API Source: {baseURL}/settings
    Pass Condition: At least one access policy or setting is actively enforced

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
        policies = data.get("data", data.get("policies", data.get("settings", data.get("results", data.get("items", [])))))

        if isinstance(policies, list):
            total = len(policies)
            active = []
            for p in policies:
                enabled = p.get("enabled", p.get("active", p.get("status", "")))
                if enabled is True:
                    active.append(p)
                elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                    active.append(p)
            activeCount = len(active)
        elif isinstance(policies, dict):
            total = 1
            activeCount = 1 if policies.get("enabled", policies.get("active", False)) else 0
        else:
            total = 0
            activeCount = 0

        result = activeCount > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePolicies": activeCount,
            "totalPolicies": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
