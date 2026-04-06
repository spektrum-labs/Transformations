import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Vectra Detect

    Checks: Whether Vectra triage rules are configured for detection management
    API Source: {baseURL}/api/v2.5/rules
    Pass Condition: At least one triage rule exists and is active

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
        rules = data.get("results", data.get("data", data.get("rules", data.get("items", []))))

        if not isinstance(rules, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activePolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected rules response format"
            }

        total = len(rules)
        active = []
        for r in rules:
            enabled = r.get("enabled", r.get("active", r.get("status", "")))
            if enabled is True:
                active.append(r)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(r)
            elif r.get("id") and enabled is not False:
                active.append(r)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
