import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for HCL BigFix

    Checks: Whether BigFix has managed computers in its inventory
    API Source: {baseURL}/computers
    Pass Condition: At least one computer endpoint is registered and managed

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "totalComputers": int}
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
        computers = data.get("data", data.get("computers", data.get("results", data.get("items", []))))

        if isinstance(computers, list):
            total = len(computers)
        elif isinstance(computers, dict):
            total = computers.get("totalCount", computers.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalComputers": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
