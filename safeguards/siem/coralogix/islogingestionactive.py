import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Coralogix

    Checks: Whether log integrations are configured and actively ingesting
    API Source: /api/v1/external/integrations
    Pass Condition: At least one integration is configured and active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogIngestionActive": boolean, "activeIntegrations": int, "totalIntegrations": int}
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
        integrations = data.get("integrations", data.get("data", data.get("items", [])))
        if not isinstance(integrations, list):
            return {
                "isLogIngestionActive": False,
                "activeIntegrations": 0,
                "totalIntegrations": 0,
                "error": "Unexpected integrations response format"
            }

        total = len(integrations)
        active = [
            i for i in integrations
            if i.get("active", i.get("enabled", False)) is True
        ]

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogIngestionActive": result,
            "activeIntegrations": len(active),
            "totalIntegrations": total
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
