import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Oort (Cisco Identity Intelligence)

    Checks: Whether identities are being tracked in the Oort platform
    API Source: {baseURL}/v1/identities
    Pass Condition: At least one identity is being monitored

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
        identities = data.get("data", data.get("results", data.get("items", data.get("identities", []))))

        if not isinstance(identities, list):
            identities = [identities] if identities else []

        total = len(identities)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalIdentities": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
