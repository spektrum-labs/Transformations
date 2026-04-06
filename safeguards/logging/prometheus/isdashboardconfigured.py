import json
import ast


def transform(input):
    """
    Evaluates isDashboardConfigured for Prometheus

    Checks: Whether the Prometheus runtime is healthy and operational
    API Source: https://{host}:9090/api/v1/status/runtimeinfo
    Pass Condition: API returns valid runtime information

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
        status = data.get("status", "")
        prom_data = data.get("data", {})
        start_time = prom_data.get("startTime", "") if isinstance(prom_data, dict) else ""

        result = status == "success" or len(str(start_time)) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isDashboardConfigured": result,
            "serviceHealthy": result
        }

    except Exception as e:
        return {"isDashboardConfigured": False, "error": str(e)}
