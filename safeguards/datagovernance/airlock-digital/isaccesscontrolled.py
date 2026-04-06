import json
import ast


def transform(input):
    """
    Evaluates isAccessControlled for Airlock Digital

    Checks: Whether at least one allowlist/blocklist policy is configured
    API Source: https://{server}:3129/api/v1/policies
    Pass Condition: At least one policy exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAccessControlled": boolean, "activePolicies": int, "totalPolicies": int}
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
        policies = data.get("policies", data.get("data", {}).get("policies", data.get("items", [])))

        if not isinstance(policies, list):
            policies = [policies] if policies else []

        total = len(policies)
        active = [p for p in policies if p.get("enabled", True)] if policies else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAccessControlled": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isAccessControlled": False, "error": str(e)}
