import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for runZero

    Checks: Whether scan sites are configured for network discovery
    API Source: {baseURL}/api/v1.0/export/org/sites.json
    Pass Condition: At least one scan site is configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activeSites": int, "totalSites": int}
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
        sites = data if isinstance(data, list) else data.get("data", data.get("results", data.get("items", data.get("sites", []))))

        if not isinstance(sites, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activeSites": 0,
                "totalSites": 0,
                "error": "Unexpected sites response format"
            }

        total = len(sites)
        active = [
            s for s in sites
            if s.get("enabled", True) is not False
            and s.get("status", "").lower() != "disabled"
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activeSites": len(active),
            "totalSites": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
