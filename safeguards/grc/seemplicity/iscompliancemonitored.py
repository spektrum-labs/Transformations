import json
import ast


def transform(input):
    """
    Evaluates isComplianceMonitored for Seemplicity

    Checks: Whether remediation policies are configured and active
    API Source: {baseURL}/api/v1/policies
    Pass Condition: At least 1 policy exists with an active or enabled status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isComplianceMonitored": boolean, "activePolicies": int, "totalPolicies": int}
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
        policies = data.get("results", data.get("data", data.get("items", data.get("policies", []))))

        if not isinstance(policies, list):
            return {
                "isComplianceMonitored": False,
                "activePolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected policies response format"
            }

        total = len(policies)
        active = [
            p for p in policies
            if str(p.get("status", "")).lower() in ("active", "enabled", "running")
        ]
        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isComplianceMonitored": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isComplianceMonitored": False, "error": str(e)}
