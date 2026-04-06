import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for BambooHR

    Checks: Whether the employee directory is accessible and populated
    API Source: GET https://api.bamboohr.com/api/gateway.php/{subdomain}/v1/employees/directory
    Pass Condition: At least one employee record exists

    Parameters:
        input (dict): JSON data containing API response from directory endpoint

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
        employees = data.get("employees", data.get("data", data.get("items", [])))
        if not isinstance(employees, list):
            employees = []

        result = len(employees) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "employeeCount": len(employees)
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
