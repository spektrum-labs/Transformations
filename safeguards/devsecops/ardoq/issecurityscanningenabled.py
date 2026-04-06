import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Ardoq

    Checks: Whether components are managed in the Ardoq architecture repository
    API Source: {baseURL}/api/v2/components
    Pass Condition: At least one component exists in the repository

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "activeComponents": int, "totalComponents": int}
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
        components = data.get("values", data.get("data", data.get("components", data.get("items", []))))

        if not isinstance(components, list):
            total_count = data.get("totalCount", data.get("total", data.get("count", 0)))
            if isinstance(total_count, int) and total_count > 0:
                return {
                    "isSecurityScanningEnabled": True,
                    "activeComponents": total_count,
                    "totalComponents": total_count
                }
            return {
                "isSecurityScanningEnabled": False,
                "activeComponents": 0,
                "totalComponents": 0,
                "error": "Unexpected response format"
            }

        total = len(components)
        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "activeComponents": total,
            "totalComponents": total
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
