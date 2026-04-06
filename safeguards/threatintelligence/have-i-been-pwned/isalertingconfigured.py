import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Have I Been Pwned.

    Checks: At least one domain is subscribed for breach notification monitoring.
    API Source: GET https://haveibeenpwned.com/api/v3/subscribeddomains
    Pass Condition: Response contains a non-empty list of subscribed domains.

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

        # Check for subscribed domains
        domains = data if isinstance(data, list) else data.get("domains", data.get("results", data.get("items", [])))
        if isinstance(domains, list) and len(domains) > 0:
            result = True
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
