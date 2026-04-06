import json
import ast


def transform(input):
    """
    Evaluates isSecurityPolicyEnforced for Nexthink

    Checks: Whether active campaigns (policies/remediations) are configured
    API Source: {baseURL}/api/v1/campaigns
    Pass Condition: At least one active campaign exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityPolicyEnforced": boolean, "activeCampaigns": int, "totalCampaigns": int}
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
        campaigns = data.get("data", data.get("results", data.get("items", data.get("campaigns", []))))

        if not isinstance(campaigns, list):
            return {
                "isSecurityPolicyEnforced": False,
                "activeCampaigns": 0,
                "totalCampaigns": 0,
                "error": "Unexpected campaigns response format"
            }

        total = len(campaigns)
        active = [
            c for c in campaigns
            if c.get("enabled", False) is True
            or str(c.get("enabled", "")).lower() in ("true", "1", "yes")
            or c.get("status", "").lower() in ("enabled", "active", "running", "published")
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityPolicyEnforced": result,
            "activeCampaigns": len(active),
            "totalCampaigns": total
        }

    except Exception as e:
        return {"isSecurityPolicyEnforced": False, "error": str(e)}
