import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Dropbox (Cloud Storage)

    Checks: Whether the Dropbox account is accessible and returns valid account data
    API Source: POST https://api.dropboxapi.com/2/users/get_current_account
    Pass Condition: API returns a valid account object with account_id

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

        account_id = data.get("account_id", "")
        email = data.get("email", "")
        name = data.get("name", {})
        display_name = name.get("display_name", "") if isinstance(name, dict) else ""

        if account_id or email:
            result = True
        elif display_name:
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
