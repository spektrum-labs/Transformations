import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Glean (Enterprise Search)

    Checks: Whether the Glean search endpoint returns results
    API Source: POST {baseURL}/rest/api/v1/search
    Pass Condition: API returns a valid search response

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean}
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

        results = data.get("results", None)
        total_count = data.get("totalCount", None)

        if results is not None:
            result = True
        elif total_count is not None:
            result = True
        elif isinstance(data, dict) and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}
    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
