import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for JetBrains Space

    Checks: Whether code reviews and quality gates are actively configured
    API Source: {baseURL}/api/http/projects/code-reviews
    Pass Condition: At least one code review exists indicating active scanning workflows

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "reviewCount": int, "activeReviews": int}
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
        reviews = data.get("data", data.get("items", data.get("results", [])))

        if not isinstance(reviews, list):
            reviews = [data] if data else []

        total = len(reviews)
        active = [
            r for r in reviews
            if isinstance(r, dict) and r.get("state", "").lower() in ("opened", "open", "active")
        ]

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "reviewCount": total,
            "activeReviews": len(active)
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
