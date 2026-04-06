import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Prometheus

    Checks: Whether at least one alerting rule group is configured
    API Source: https://{host}:9090/api/v1/rules?type=alert
    Pass Condition: At least one alert rule group exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "activeAlerts": int, "totalAlerts": int}
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
        prom_data = data.get("data", {})
        groups = prom_data.get("groups", []) if isinstance(prom_data, dict) else []

        if not isinstance(groups, list):
            groups = [groups] if groups else []

        total = len(groups)
        rule_count = sum(len(g.get("rules", [])) for g in groups if isinstance(g, dict))

        result = rule_count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "activeAlerts": rule_count,
            "totalAlerts": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
