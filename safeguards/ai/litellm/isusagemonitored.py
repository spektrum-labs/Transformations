import json
import ast


def transform(input):
    """
    Evaluates isUsageMonitored for LiteLLM Proxy

    Checks: Whether spend/usage logging is active on the proxy
    API Source: GET {baseURL}/global/spend/logs
    Pass Condition: A valid spend logs response is returned (even if empty)

    Parameters:
        input (dict): JSON data containing API response from spend logs endpoint

    Returns:
        dict: {"isUsageMonitored": boolean, "logCount": int}
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
        if error:
            return {"isUsageMonitored": False, "logCount": 0}

        logs = data.get("data", data.get("logs", data.get("spend_logs", [])))
        if isinstance(logs, list):
            result = True
            log_count = len(logs)
        elif isinstance(data, list):
            result = True
            log_count = len(data)
        else:
            result = True
            log_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isUsageMonitored": result,
            "logCount": log_count
        }

    except Exception as e:
        return {"isUsageMonitored": False, "error": str(e)}
