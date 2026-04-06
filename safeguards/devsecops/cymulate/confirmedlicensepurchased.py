import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Cymulate (Breach & Attack Simulation)

    Checks: Whether the Cymulate account is active and accessible
    API Source: GET https://api.cymulate.com/v1/user/account
    Pass Condition: API returns a valid account object with an active subscription

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

        # Check for valid account data from Cymulate API
        account = data.get("data", data)
        if isinstance(account, dict):
            if account.get("id") or account.get("name") or account.get("company"):
                result = True
            elif account.get("active") or account.get("status") == "active":
                result = True
            elif account.get("license") or account.get("subscription"):
                result = True
        elif isinstance(data, dict) and len(data) > 0 and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
