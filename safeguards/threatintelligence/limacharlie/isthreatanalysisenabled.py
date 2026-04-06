import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for LimaCharlie.

    Checks: Insight detection objects are accessible from the org.
    API Source: GET https://api.limacharlie.io/v1/insight/{oid}/objects/detections
    Pass Condition: Response contains detection insight data or the endpoint is accessible.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean}
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

        # Check for insight detection data
        if isinstance(data, list) and len(data) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"isThreatAnalysisEnabled": result}

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
