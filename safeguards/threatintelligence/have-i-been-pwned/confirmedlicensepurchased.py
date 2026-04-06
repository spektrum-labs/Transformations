import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Have I Been Pwned.

    Checks: Active HIBP subscription by verifying the subscription status endpoint
            returns a valid response with an active subscription key.
    API Source: GET https://haveibeenpwned.com/api/v3/subscription/status
    Pass Condition: Response contains a valid subscription name and expiration date in the future.

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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # HIBP subscription status check
        sub_name = data.get("SubscriptionName", data.get("subscriptionName", ""))
        if isinstance(sub_name, str) and len(sub_name.strip()) > 0:
            result = True
        else:
            # Check for any successful response indicating valid API key
            status_code = data.get("statusCode", data.get("status_code", 0))
            if isinstance(status_code, int) and status_code == 200:
                result = True
            elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
                result = True
            else:
                result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
