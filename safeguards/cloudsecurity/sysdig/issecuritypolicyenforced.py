import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Sysdig

    Checks: Whether security policies are configured and actively enforced in Sysdig Secure
    API Source: {baseURL}/api/v2/policies
    Pass Condition: At least one policy exists and is enabled

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
        policies = data.get("data", data.get("policies", data.get("results", data.get("items", []))))

        if not isinstance(policies, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activePolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected policies response format"
            }

        total = len(policies)
        active = []
        for p in policies:
            enabled = p.get("enabled", p.get("isEnabled", p.get("active", p.get("status", ""))))
            if enabled is True:
                active.append(p)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(p)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
