import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Oort (Cisco Identity Intelligence)

    Checks: Whether identity checks are configured and active
    API Source: {baseURL}/v1/checks
    Pass Condition: At least one active identity check exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activeChecks": int, "totalChecks": int}
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
        checks = data.get("data", data.get("results", data.get("items", data.get("checks", []))))

        if not isinstance(checks, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activeChecks": 0,
                "totalChecks": 0,
                "error": "Unexpected checks response format"
            }

        total = len(checks)
        active = [
            c for c in checks
            if c.get("enabled", False) is True
            or str(c.get("enabled", "")).lower() in ("true", "1", "yes")
            or c.get("status", "").lower() in ("enabled", "active", "passing", "failing")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activeChecks": len(active),
            "totalChecks": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
