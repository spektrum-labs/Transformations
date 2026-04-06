import json
import ast


def transform(input):
    """
    Evaluates isPatchManagementEnabled for Kandji (EPP)

    Checks: Whether auto-app updates and OS update enforcement are configured
    API Source: GET /api/v1/blueprints
    Pass Condition: At least one blueprint exists with update enforcement configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPatchManagementEnabled": boolean, ...metadata}
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

        # ── EVALUATION LOGIC ──
        result = False
        blueprints = data if isinstance(data, list) else data.get("results", data.get("blueprints", data.get("data", [])))
        if not isinstance(blueprints, list):
            blueprints = []

        total = len(blueprints)
        with_updates = 0
        for bp in blueprints:
            params = bp.get("params", bp.get("parameters", {}))
            name = bp.get("name", "").lower()
            if isinstance(params, dict):
                os_updates = params.get("os_update_enforcement", params.get("auto_apps", False))
                if os_updates:
                    with_updates += 1
            if "update" in name or "patch" in name:
                with_updates += 1

        if total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isPatchManagementEnabled": result,
            "blueprintsWithUpdates": with_updates,
            "totalBlueprints": total
        }

    except Exception as e:
        return {"isPatchManagementEnabled": False, "error": str(e)}
