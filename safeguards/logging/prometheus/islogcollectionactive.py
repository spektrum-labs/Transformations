import json
import ast


def transform(input):
    """
    Evaluates isLogCollectionActive for Prometheus

    Checks: Whether at least one scrape target is active
    API Source: https://{host}:9090/api/v1/targets
    Pass Condition: At least one active target exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isLogCollectionActive": boolean, "activeSources": int, "totalSources": int}
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
        active_targets = prom_data.get("activeTargets", []) if isinstance(prom_data, dict) else []

        if not isinstance(active_targets, list):
            active_targets = [active_targets] if active_targets else []

        total = len(active_targets)
        up_targets = [t for t in active_targets if t.get("health", "").lower() == "up"] if active_targets else []

        result = len(up_targets) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isLogCollectionActive": result,
            "activeSources": len(up_targets),
            "totalSources": total
        }

    except Exception as e:
        return {"isLogCollectionActive": False, "error": str(e)}
