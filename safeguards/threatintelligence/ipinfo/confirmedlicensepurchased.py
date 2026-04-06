import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for IPinfo.

    Checks: Active IPinfo account by verifying the /me endpoint returns valid token data.
    API Source: GET https://ipinfo.io/me
    Pass Condition: Response contains valid account details with a token.

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

        # Check for valid token/account info
        token = data.get("token", data.get("access_token", ""))
        ip = data.get("ip", "")

        if isinstance(token, str) and len(token.strip()) > 0:
            result = True
        elif isinstance(ip, str) and len(ip.strip()) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
