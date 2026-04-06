import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for HubSpot (CRM / Marketing Platform)

    Checks: Whether the HubSpot account is accessible and returns valid account details
    API Source: GET https://api.hubapi.com/account-info/v3/details
    Pass Condition: API returns a valid account object with portalId

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        if portal_id and int(portal_id) > 0:
            result = True
        elif account_type:
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
