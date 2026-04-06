import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Domo

    Checks: Whether Domo has datasets registered in the platform
    API Source: {baseURL}/v1/datasets
    Pass Condition: At least one dataset exists in the Domo instance

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "totalDatasets": int}
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
        datasets = data.get("data", data.get("datasets", data.get("results", data.get("items", []))))

        if isinstance(datasets, list):
            total = len(datasets)
        elif isinstance(datasets, dict):
            total = datasets.get("totalCount", datasets.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalDatasets": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
