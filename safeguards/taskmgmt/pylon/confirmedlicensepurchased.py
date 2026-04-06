import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Pylon

    Checks: Whether the Pylon account is active by verifying the me endpoint
    API Source: https://api.usepylon.com/me
    Pass Condition: API returns a successful response with account information

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "accountName": str}
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
        account_name = data.get("name", data.get("email", ""))
        account_id = data.get("id", "")

        result = bool(account_id) or bool(account_name)
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "accountName": account_name
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
