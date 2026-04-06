import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for SentinelOne DataSet

    Checks: Whether alert notification addresses are configured
    API Source: /api/listAlertAddresses
    Pass Condition: At least one alert address or notification channel is configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "alertAddressCount": int}
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
        addresses = data.get("addresses", data.get("alertAddresses", data.get("data", [])))
        if not isinstance(addresses, list):
            addresses = []

        count = len(addresses)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "alertAddressCount": count
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
