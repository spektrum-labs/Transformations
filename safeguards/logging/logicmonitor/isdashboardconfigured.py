import json
import ast


def transform(input):
    """
    Evaluates isDashboardConfigured for LogicMonitor

    Checks: Whether at least one dashboard is configured
    API Source: https://{company}.logicmonitor.com/santaba/rest/dashboard/dashboards
    Pass Condition: At least one dashboard exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isDashboardConfigured": boolean, "totalDashboards": int}
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
        items = data.get("items", data.get("data", {}).get("items", []))
        total = data.get("total", data.get("data", {}).get("total", 0))

        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isDashboardConfigured": result,
            "totalDashboards": total
        }

    except Exception as e:
        return {"isDashboardConfigured": False, "error": str(e)}
