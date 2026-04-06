import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Grip Security

    Checks: Whether SaaS applications have been discovered and inventoried
    API Source: {baseURL}/api/v1/saas
    Pass Condition: At least 1 SaaS application exists in the inventory

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
        saas_apps = data.get("saas", data.get("results", data.get("data", data.get("items", []))))

        if isinstance(saas_apps, list):
            total = len(saas_apps)
        elif isinstance(saas_apps, dict):
            total = saas_apps.get("total", saas_apps.get("count", len(saas_apps)))
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
