import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for ADP HR/Payroll

    Checks: Whether the workers API returns data
    API Source: GET https://api.adp.com/hr/v2/workers
    Pass Condition: At least one worker record is returned

    Parameters:
        input (dict): JSON data containing API response from workers endpoint

    Returns:
        dict: {"isServiceEnabled": boolean, "workerCount": int}
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
        workers = data.get("workers", data.get("data", data.get("items", [])))
        if not isinstance(workers, list):
            workers = []

        result = len(workers) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "workerCount": len(workers)
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
