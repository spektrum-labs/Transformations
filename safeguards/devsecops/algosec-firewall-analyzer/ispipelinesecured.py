import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for AlgoSec Firewall Analyzer

    Checks: Whether security zone profiles are configured for network policy enforcement
    API Source: {baseURL}/afa/api/v1/security_zones/get_profiles_list
    Pass Condition: At least one security zone profile is configured and active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "activeProfiles": int, "totalProfiles": int}
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
        profiles = data.get("data", data.get("profiles", data.get("results", data.get("items", []))))

        if not isinstance(profiles, list):
            return {
                "isPipelineSecured": False,
                "activeProfiles": 0,
                "totalProfiles": 0,
                "error": "Unexpected response format"
            }

        total = len(profiles)
        active = []
        for profile in profiles:
            enabled = profile.get("enabled", profile.get("active", profile.get("status", "")))
            if enabled is True:
                active.append(profile)
            elif isinstance(enabled, str) and enabled.lower() in ("true", "active", "enabled"):
                active.append(profile)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "activeProfiles": len(active),
            "totalProfiles": total
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
