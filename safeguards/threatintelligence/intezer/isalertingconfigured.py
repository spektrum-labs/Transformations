import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Intezer.

    Checks: Alerts are configured in the Intezer platform.
    API Source: GET https://analyze.intezer.com/api/v2-0/alerts
    Pass Condition: Response contains alert configuration data.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean}
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

        # Check for alerts data
        alerts = data if isinstance(data, list) else data.get("alerts", data.get("results", data.get("items", [])))
        if isinstance(alerts, list) and len(alerts) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
