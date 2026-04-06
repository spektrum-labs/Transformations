import json
import ast


def transform(input):
    """
    Evaluates isContinuousMonitoringEnabled for HCL BigFix

    Checks: Whether BigFix actions are being executed and monitored
    API Source: {baseURL}/actions
    Pass Condition: At least one action exists, indicating active endpoint management

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isContinuousMonitoringEnabled": boolean, "totalActions": int}
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
        actions = data.get("data", data.get("actions", data.get("results", data.get("items", []))))

        if isinstance(actions, list):
            total = len(actions)
        elif isinstance(actions, dict):
            total = actions.get("totalCount", actions.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isContinuousMonitoringEnabled": result,
            "totalActions": total
        }

    except Exception as e:
        return {"isContinuousMonitoringEnabled": False, "error": str(e)}
