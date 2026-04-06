import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Sevco Security

    Checks: Whether correlated assets exist in the Sevco asset graph
    API Source: {baseURL}/v1/assets
    Pass Condition: At least one asset is correlated from data sources

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
        assets = data.get("data", data.get("results", data.get("items", data.get("assets", []))))

        if not isinstance(assets, list):
            assets = [assets] if assets else []

        total = len(assets)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalAssets": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
