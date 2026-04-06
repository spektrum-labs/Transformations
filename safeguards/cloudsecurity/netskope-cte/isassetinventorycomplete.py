import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Netskope Cloud Threat Exchange

    Checks: Whether threat indicators are being collected
    API Source: {baseURL}/api/cte/indicators
    Pass Condition: At least one threat indicator exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "totalIndicators": int}
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
        indicators = data.get("data", data.get("results", data.get("items", data.get("indicators", []))))

        if not isinstance(indicators, list):
            indicators = [indicators] if indicators else []

        total = len(indicators)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalIndicators": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
