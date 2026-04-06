import json
import ast


def transform(input):
    """
    Evaluates isBehavioralMonitoringValid for Kandji (EPP)

    Checks: Whether endpoint detection library items are assigned in blueprints
    API Source: GET /api/v1/blueprints
    Pass Condition: At least one blueprint has security-related library items active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isBehavioralMonitoringValid": boolean, ...metadata}
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

        security_keywords = ["security", "protect", "threat", "detection", "monitor",
                             "firewall", "gatekeeper", "xprotect"]
        matching = 0
        for bp in blueprints:
            name = bp.get("name", "").lower()
            item_count = bp.get("library_item_count", bp.get("libraryItemCount", 0))

            for keyword in security_keywords:
                if keyword in name:
                    matching += 1
                    break

            if isinstance(item_count, int) and item_count > 0:
                matching += 1

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isBehavioralMonitoringValid": result,
            "securityBlueprints": matching,
            "totalBlueprints": len(blueprints)
        }

    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}
