import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for WhoisXML API.

    Checks: Active WhoisXML API subscription by verifying account balance
            endpoint returns valid data with remaining credits.
    API Source: GET https://user.whoisxmlapi.com/user-service/account-balance
    Pass Condition: Account balance response contains valid balance data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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
        balance = data.get("balance", data.get("credits", data.get("data", None)))
        error = data.get("error", data.get("errors", None))

        if error:
            result = False
            status = "error"
        elif balance is not None:
            if isinstance(balance, (int, float)):
                result = balance > 0
            else:
                result = True
            status = "active" if result else "exhausted"
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
            status = "active"
        else:
            result = False
            status = "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": "unknown",
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
