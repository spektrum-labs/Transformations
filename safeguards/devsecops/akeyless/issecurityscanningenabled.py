import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Akeyless

    Checks: Whether secrets items are configured in the vault
    API Source: {baseURL}/list-items
    Pass Condition: At least one secret item exists in the vault

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "activeItems": int, "totalItems": int}
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
        items = data.get("items", data.get("data", data.get("results", data.get("secrets", []))))

        if not isinstance(items, list):
            return {
                "isSecurityScanningEnabled": False,
                "activeItems": 0,
                "totalItems": 0,
                "error": "Unexpected response format"
            }

        total = len(items)
        active = []
        for item in items:
            item_type = item.get("item_type", item.get("type", ""))
            is_enabled = item.get("is_enabled", item.get("enabled", True))
            if is_enabled is True or (isinstance(is_enabled, str) and is_enabled.lower() in ("true", "enabled")):
                active.append(item)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "activeItems": len(active),
            "totalItems": total
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
