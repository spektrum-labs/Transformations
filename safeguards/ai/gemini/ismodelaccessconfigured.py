import json
import ast


def transform(input):
    """
    Evaluates isModelAccessConfigured for Google Gemini AI

    Checks: Whether at least one Gemini model is accessible
    API Source: GET https://generativelanguage.googleapis.com/v1beta/models
    Pass Condition: At least one model is returned in the listing

    Parameters:
        input (dict): JSON data containing API response from models endpoint

    Returns:
        dict: {"isModelAccessConfigured": boolean, "modelCount": int, "models": list}
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
        models = data.get("models", data.get("data", []))

        if not isinstance(models, list):
            models = []

        model_names = [m.get("name", m.get("displayName", "")) for m in models if isinstance(m, dict)]
        result = len(model_names) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isModelAccessConfigured": result,
            "modelCount": len(model_names),
            "models": model_names[:10]
        }

    except Exception as e:
        return {"isModelAccessConfigured": False, "error": str(e)}
