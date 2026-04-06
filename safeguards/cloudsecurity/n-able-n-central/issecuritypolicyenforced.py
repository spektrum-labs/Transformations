import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for N-able N-Central

    Checks: Whether monitoring policies are configured and enforced
    API Source: {baseURL}/api/policies
    Pass Condition: At least 1 active monitoring policy exists

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
        policies = data.get("policies", data.get("data", data.get("results", data.get("items", []))))

        if not isinstance(policies, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activePolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected policies response format"
            }

        total = len(policies)

        active = [
            p for p in policies
            if p.get("enabled", False) is True
            or p.get("active", False) is True
            or str(p.get("status", "")).lower() in ("active", "enabled")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
