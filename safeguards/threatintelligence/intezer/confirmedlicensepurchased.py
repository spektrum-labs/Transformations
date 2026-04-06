import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Intezer.

    Checks: Active Intezer account by verifying the account endpoint returns valid data.
    API Source: GET https://analyze.intezer.com/api/v2-0/account
    Pass Condition: Response contains valid account details with an active status.

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

        # Check for valid account details
        account_id = data.get("account_id", data.get("id", ""))
        email = data.get("email", data.get("user_email", ""))

        if isinstance(account_id, str) and len(account_id.strip()) > 0:
            result = True
        elif isinstance(email, str) and len(email.strip()) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
