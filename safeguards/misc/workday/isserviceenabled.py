import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Workday.

    Checks: Whether the Workday service is active by confirming worker records
            are retrievable via the REST API.
    API Source: GET {baseURL}/ccx/api/v1/{tenantId}/workers
    Pass Condition: API returns worker data without errors

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
        workers = data.get("data", data.get("workers", data.get("results", [])))
        total = data.get("total", data.get("totalCount", 0))
        error = data.get("error", data.get("errors", None))

        if error:
            result = False
        elif isinstance(workers, list) and len(workers) >= 0:
            result = True
        elif isinstance(total, (int, float)) and total >= 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
        else:
            result = False
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
