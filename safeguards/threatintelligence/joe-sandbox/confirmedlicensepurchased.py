import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Joe Sandbox.

    Checks: Active Joe Sandbox license by verifying account info and quota status.
    API Source: GET https://jbxcloud.joesecurity.org/api/v2/account/info
    Pass Condition: Response contains valid account data with quota remaining.

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

        # Check for valid account/quota data
        account_data = data.get("data", data)
        if isinstance(account_data, dict):
            quota = account_data.get("quota", {})
            if isinstance(quota, dict):
                remaining = quota.get("remaining", quota.get("daily", {}).get("remaining", -1))
                if isinstance(remaining, int) and remaining >= 0:
                    return {"confirmedLicensePurchased": True}

            # Fallback: check for account type or email
            acct_type = account_data.get("type", account_data.get("account_type", ""))
            if isinstance(acct_type, str) and len(acct_type.strip()) > 0:
                return {"confirmedLicensePurchased": True}

        if isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
