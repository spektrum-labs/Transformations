import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for Delighted (Customer Feedback / NPS)

    Checks: Whether the Delighted NPS metrics are accessible
    API Source: GET https://api.delighted.com/v1/metrics.json
    Pass Condition: API returns valid NPS metrics data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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
        result = False

        # NPS metrics being accessible confirms valid configuration
        nps = data.get("nps", None)
        if nps is not None:
            result = True
        elif isinstance(data, dict) and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}
    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
