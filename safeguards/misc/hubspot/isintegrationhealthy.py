import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for HubSpot (CRM / Marketing Platform)

    Checks: Whether the HubSpot API is responding with valid Bearer token authentication
    API Source: GET https://api.hubapi.com/account-info/v3/details
    Pass Condition: API returns a valid account response confirming connectivity

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean}
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
        result = False

        portal_id = data.get("portalId", 0)
        message = data.get("message", "")
        status = data.get("status", "")

        if status == "error" or message:
            result = False
        elif portal_id and int(portal_id) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isIntegrationHealthy": result}
    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
