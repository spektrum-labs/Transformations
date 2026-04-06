import json
import ast


def transform(input):
    """
    Evaluates isDashboardConfigured for Cribl

    Checks: Whether the Cribl API is healthy and pipeline processing is operational
    API Source: https://{workspace}.cribl.cloud/api/v1/health
    Pass Condition: API returns a healthy status

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isDashboardConfigured": boolean, "serviceHealthy": boolean}
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
        error = data.get("error", None)
        healthy = data.get("healthy", data.get("status", None))

        result = error is None and healthy is not None
        # -- END EVALUATION LOGIC --

        return {
            "isDashboardConfigured": result,
            "serviceHealthy": result
        }

    except Exception as e:
        return {"isDashboardConfigured": False, "error": str(e)}
