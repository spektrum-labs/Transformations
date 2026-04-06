import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Astrix Security

    Checks: Whether the Astrix platform has discovered non-human identities
    API Source: {baseURL}/v1/identities
    Pass Condition: At least one non-human identity is discovered and inventoried

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "totalIdentities": int}
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
        identities = data.get("data", data.get("identities", data.get("results", data.get("items", []))))

        if isinstance(identities, list):
            total = len(identities)
        elif isinstance(identities, dict):
            total = identities.get("totalCount", identities.get("total", 0))
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalIdentities": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
