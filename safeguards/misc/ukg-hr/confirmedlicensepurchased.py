import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for UKG HR Service Delivery.

    Checks: Active UKG HR subscription by verifying successful OAuth authentication
            and employee data retrieval from the API.
    API Source: GET {baseURL}/api/v2/client/employees
    Pass Condition: API returns a valid response with employee data or a non-error status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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
        employees = data.get("employees", data.get("data", data.get("results", [])))
        error = data.get("error", data.get("errors", None))

        if error:
            result = False
            status = "error"
        elif isinstance(employees, list):
            result = True
            status = "active"
        elif isinstance(data, dict) and len(data) > 0:
            result = True
            status = "active"
        else:
            result = False
            status = "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": "unknown",
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
