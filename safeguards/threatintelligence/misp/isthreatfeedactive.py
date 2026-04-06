import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for MISP.

    Checks: Threat indicator attributes are accessible via restSearch.
    API Source: POST {baseURL}/attributes/restSearch
    Pass Condition: Response contains a non-empty list of indicator attributes.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatFeedActive": boolean}
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

        # Check for MISP attribute data
        response_obj = data.get("response", data)
        if isinstance(response_obj, dict):
            attributes = response_obj.get("Attribute", response_obj.get("attribute", []))
        elif isinstance(response_obj, list):
            attributes = response_obj
        else:
            attributes = []

        if isinstance(attributes, list) and len(attributes) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data and "message" not in data:
            result = True
        else:
            result = False

        return {"isThreatFeedActive": result}

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
