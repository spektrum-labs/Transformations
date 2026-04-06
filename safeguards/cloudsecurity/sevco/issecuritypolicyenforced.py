import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Sevco Security

    Checks: Whether data source integrations are configured and active
    API Source: {baseURL}/v1/sources
    Pass Condition: At least one active data source integration exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activeSources": int, "totalSources": int}
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
        sources = data.get("data", data.get("results", data.get("items", data.get("sources", []))))

        if not isinstance(sources, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activeSources": 0,
                "totalSources": 0,
                "error": "Unexpected sources response format"
            }

        total = len(sources)
        active = [
            s for s in sources
            if s.get("enabled", False) is True
            or str(s.get("enabled", "")).lower() in ("true", "1", "yes")
            or s.get("status", "").lower() in ("enabled", "active", "connected", "healthy")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activeSources": len(active),
            "totalSources": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
