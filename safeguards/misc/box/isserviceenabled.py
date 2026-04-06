import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Box Cloud Content Management

    Checks: Whether root folder items are accessible
    API Source: GET https://api.box.com/2.0/folders/0/items
    Pass Condition: A valid folder items response is returned

    Parameters:
        input (dict): JSON data containing API response from folders endpoint

    Returns:
        dict: {"isServiceEnabled": boolean, "itemCount": int}
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
        entries = data.get("entries", data.get("data", data.get("items", [])))
        total_count = data.get("total_count", data.get("total", 0))

        if not isinstance(entries, list):
            entries = []

        result = True
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "itemCount": len(entries) if entries else int(total_count)
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
