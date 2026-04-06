import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Anthropic (Claude AI)

    Checks: Whether the Anthropic API key is valid and returns model data
    API Source: GET https://api.anthropic.com/v1/models
    Pass Condition: A successful API response with model listing

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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
        error = data.get("error", None)
        if error:
            return {"confirmedLicensePurchased": False, "status": "error"}

        models = data.get("data", data.get("models", []))
        if isinstance(models, list) and len(models) > 0:
            result = True
            status = "active"
        else:
            result = False
            status = "no_models"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
