import json
import ast


def transform(input):
    """
    Evaluates isForensicsEnabled for FireHydrant

    Checks: Whether active services and their monitoring status are configured
    API Source: https://api.firehydrant.io/v1/services
    Pass Condition: At least one service is registered and monitored

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isForensicsEnabled": boolean, "totalServices": int}
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
        services = data.get("services", data.get("data", data.get("results", [])))
        if not isinstance(services, list):
            services = []

        total = len(services)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isForensicsEnabled": result,
            "totalServices": total
        }

    except Exception as e:
        return {"isForensicsEnabled": False, "error": str(e)}
