import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Grip Security

    Checks: Whether SaaS security policies are configured and enforced
    API Source: {baseURL}/api/v1/policies
    Pass Condition: At least 1 enabled security policy exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "enabledPolicies": int, "totalPolicies": int}
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
        policies = data.get("policies", data.get("results", data.get("data", data.get("items", []))))

        if not isinstance(policies, list):
            return {
                "isSecurityPolicyEnforced": False,
                "enabledPolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected policies response format"
            }

        total = len(policies)

        enabled = [
            p for p in policies
            if p.get("enabled", False) is True
            or p.get("active", False) is True
            or str(p.get("status", "")).lower() in ("enabled", "active")
        ]

        result = len(enabled) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "enabledPolicies": len(enabled),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
