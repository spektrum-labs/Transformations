import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Intel Owl.

    Checks: Tags are configured in the Intel Owl instance for alert categorization.
    API Source: GET {baseURL}/api/tags
    Pass Condition: Response contains a non-empty list of configured tags.

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

        # Check for tags configuration
        tags = data if isinstance(data, list) else data.get("results", data.get("tags", data.get("items", [])))
        if isinstance(tags, list) and len(tags) > 0:
            result = True
        elif isinstance(data, dict) and "count" in data:
            count = data.get("count", 0)
            result = isinstance(count, int) and count > 0
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
