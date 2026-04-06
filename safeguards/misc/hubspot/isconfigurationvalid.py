import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for HubSpot (CRM / Marketing Platform)

    Checks: Whether the HubSpot account info and settings are accessible
    API Source: GET https://api.hubapi.com/account-info/v3/details
    Pass Condition: API returns valid account configuration with portalId and accountType

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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
        account_type = data.get("accountType", "")
        time_zone = data.get("timeZone", "")
        currency = data.get("currency", "")

        if portal_id and account_type:
            result = True
        elif portal_id and (time_zone or currency):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}
    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
