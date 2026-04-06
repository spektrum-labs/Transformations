import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Greenhouse (Recruiting / ATS)

    Checks: Whether the Greenhouse candidates endpoint is accessible
    API Source: GET https://harvest.greenhouse.io/v1/candidates
    Pass Condition: API returns a valid candidate listing response

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

        candidates = data.get("candidates", data) if isinstance(data, dict) else data
        if isinstance(candidates, list):
            result = True
        elif isinstance(data, list):
            result = True
        elif isinstance(data, dict) and not data.get("errors"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}
    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
