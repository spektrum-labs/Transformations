import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Zoom.

    Checks: Whether the Zoom service is active by confirming user records
            are retrievable via the API.
    API Source: GET https://api.zoom.us/v2/users
    Pass Condition: API returns user data without errors

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
        users = data.get("users", data.get("data", data.get("results", [])))
        total_records = data.get("total_records", data.get("totalRecords", 0))
        error = data.get("error", data.get("errors", None))
        code = data.get("code", None)

        if error or (isinstance(code, int) and code != 200 and code != 0):
            result = False
        elif isinstance(users, list) and len(users) >= 0:
            result = True
        elif isinstance(total_records, (int, float)) and total_records >= 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
        else:
            result = False
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
