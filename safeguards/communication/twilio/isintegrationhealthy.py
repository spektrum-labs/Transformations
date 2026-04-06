import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Twilio

    Checks: Whether the Twilio API is responding and the account is active
    API Source: https://api.twilio.com/2010-04-01/Accounts/{accountSid}.json
    Pass Condition: Account status is 'active'

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "accountStatus": str, "accountType": str}
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
        status = data.get("status", "")
        account_type = data.get("type", "")

        result = str(status).lower() == "active"
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "accountStatus": status,
            "accountType": account_type
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
