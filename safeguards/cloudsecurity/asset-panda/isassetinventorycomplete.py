import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Asset Panda

    Checks: Whether the Asset Panda entity list contains tracked assets
    API Source: {baseURL}/v3/entities
    Pass Condition: At least one asset entity exists in the inventory

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "totalAssets": int}
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
        entities = data.get("data", data.get("entities", data.get("results", data.get("items", []))))

        if isinstance(entities, list):
            total = len(entities)
        elif isinstance(entities, dict):
            total = entities.get("totalCount", entities.get("total", entities.get("totals", {}).get("entities", 0)))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalAssets": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
