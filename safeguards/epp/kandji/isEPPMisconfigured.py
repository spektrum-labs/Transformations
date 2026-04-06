import json
import ast


def transform(input):
    """
    Evaluates isEPPMisconfigured for Kandji (EPP)

    Checks: Whether blueprints have incomplete or misconfigured library items
    API Source: GET /api/v1/blueprints
    Pass Condition: Returns True if any blueprint has zero library items assigned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isEPPMisconfigured": boolean, ...metadata}
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

        misconfigured = 0
        for bp in blueprints:
            source_type = bp.get("source_type", "")
            item_count = bp.get("library_item_count", bp.get("libraryItemCount", -1))
            enrollment_count = bp.get("enrollment_code_count", 0)

            if isinstance(item_count, int) and item_count == 0:
                misconfigured += 1

        result = misconfigured > 0
        # ── END EVALUATION LOGIC ──

        return {
            "isEPPMisconfigured": result,
            "misconfiguredBlueprints": misconfigured,
            "totalBlueprints": len(blueprints)
        }

    except Exception as e:
        return {"isEPPMisconfigured": False, "error": str(e)}
