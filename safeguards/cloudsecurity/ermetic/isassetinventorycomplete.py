import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Ermetic (Tenable Cloud Security)

    Checks: Whether cloud resources have been discovered and inventoried
    API Source: {baseURL}/api/v1/inventory/resources
    Pass Condition: At least 1 cloud resource exists in the inventory

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
        resources = data.get("resources", data.get("results", data.get("data", data.get("items", []))))

        if isinstance(resources, list):
            total = len(resources)
        elif isinstance(resources, dict):
            total = resources.get("total", resources.get("count", len(resources)))
        else:
            total = 0

        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalAssets": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
