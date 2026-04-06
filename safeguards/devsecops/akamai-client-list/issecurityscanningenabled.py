import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Akamai Client List

    Checks: Whether client reputation lists are configured and actively used
    API Source: {baseURL}/client-lists/v1/lists
    Pass Condition: At least one client list exists and is in use

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "activeLists": int, "totalLists": int}
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
        lists = data.get("content", data.get("data", data.get("lists", data.get("items", []))))

        if not isinstance(lists, list):
            return {
                "isSecurityScanningEnabled": False,
                "activeLists": 0,
                "totalLists": 0,
                "error": "Unexpected response format"
            }

        total = len(lists)
        active = []
        for item in lists:
            item_type = item.get("type", "")
            items_count = item.get("itemsCount", item.get("itemCount", 0))
            if items_count and items_count > 0:
                active.append(item)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "activeLists": len(active),
            "totalLists": total
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
