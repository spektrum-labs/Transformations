import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Rippling

    Checks: Whether employees are retrievable from Rippling
    API Source: https://rest.ripplingapis.com/employees
    Pass Condition: The API returns an employees array

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean, "employeeCount": int}
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
        employees = data if isinstance(data, list) else data.get("employees", data.get("data", []))
        if isinstance(employees, list):
            result = True
            employee_count = len(employees)
        else:
            result = bool(data) and "error" not in data
            employee_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "employeeCount": employee_count
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
