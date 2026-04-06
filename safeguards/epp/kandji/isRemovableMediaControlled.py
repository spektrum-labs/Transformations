import json
import ast


def transform(input):
    """
    Evaluates isRemovableMediaControlled for Kandji (EPP)

    Checks: Whether device restriction profiles control external storage
    API Source: GET /api/v1/blueprints
    Pass Condition: At least one blueprint contains restriction profiles for
                    external storage or removable media

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRemovableMediaControlled": boolean, ...metadata}
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

        media_keywords = ["removable", "usb", "external", "storage", "media", "restriction"]
        matching = 0
        for bp in blueprints:
            name = bp.get("name", "").lower()
            for keyword in media_keywords:
                if keyword in name:
                    matching += 1
                    break
            params = bp.get("params", bp.get("parameters", {}))
            if isinstance(params, dict):
                external_storage = params.get("allow_external_storage", None)
                if external_storage is False:
                    matching += 1

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isRemovableMediaControlled": result,
            "matchingBlueprints": matching,
            "totalBlueprints": len(blueprints)
        }

    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}
