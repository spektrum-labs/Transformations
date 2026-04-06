import json
import ast


def transform(input):
    """
    Evaluates isDashboardConfigured for Grafana

    Checks: Whether at least one dashboard exists in Grafana
    API Source: https://{instance}.grafana.net/api/search?type=dash-db
    Pass Condition: At least one dashboard is returned

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
        dashboards = data if isinstance(data, list) else data.get("dashboards", data.get("data", data.get("items", [])))

        if not isinstance(dashboards, list):
            dashboards = [dashboards] if dashboards else []

        total = len(dashboards)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isDashboardConfigured": result,
            "totalDashboards": total
        }

    except Exception as e:
        return {"isDashboardConfigured": False, "error": str(e)}
