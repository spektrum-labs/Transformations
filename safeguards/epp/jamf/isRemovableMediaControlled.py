import json
import ast


def transform(input):
    """
    Evaluates isRemovableMediaControlled for Jamf Pro (EPP)

    Checks: Whether restriction profiles control removable media on managed devices
    API Source: GET /api/v1/policies
    Pass Condition: At least one policy or profile restricts external storage or USB

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRemovableMediaControlled": boolean, ...metadata}
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

        # ── EVALUATION LOGIC ──
        result = False
        policies = data.get("results", data.get("policies", data.get("data", [])))
        if not isinstance(policies, list):
            policies = []

        media_keywords = ["removable", "usb", "external", "storage", "media", "restriction", "device control"]
        matching = 0
        for p in policies:
            name = p.get("name", "").lower()
            category = p.get("category", {})
            cat_name = category.get("name", "").lower() if isinstance(category, dict) else ""
            for keyword in media_keywords:
                if keyword in name or keyword in cat_name:
                    matching += 1
                    break

        if matching > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "isRemovableMediaControlled": result,
            "matchingPolicies": matching,
            "totalPolicies": len(policies)
        }

    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}
