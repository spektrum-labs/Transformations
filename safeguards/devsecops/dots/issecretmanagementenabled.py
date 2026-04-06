import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Dots (Payment/Payout API Platform)

    Checks: Whether the Dots application is configured and operational
    API Source: GET https://api.dots.dev/api/v2/app
    Pass Condition: Application status indicates active configuration with webhook support

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean}
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
        result = False

        # Check if the Dots application is configured and operational
        app = data.get("data", data)
        if isinstance(app, dict):
            if app.get("id") or app.get("app_id"):
                result = True
            elif app.get("webhook_url") or app.get("webhooks"):
                result = True
            elif app.get("active") or app.get("status") == "active":
                result = True
        elif isinstance(data, dict) and len(data) > 0 and not data.get("error"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
