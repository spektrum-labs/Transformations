import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for WhatsApp Business

    Checks: Whether the WhatsApp Business phone number endpoint is responding
    API Source: https://graph.facebook.com/v23.0/{phoneNumberId}
    Pass Condition: API returns a successful response with phone number data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "phoneNumber": str, "verifiedName": str}
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
        phone_id = data.get("id", "")
        phone_number = data.get("display_phone_number", "")
        verified_name = data.get("verified_name", "")
        error = data.get("error", None)

        result = bool(phone_id) and error is None
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "phoneNumber": phone_number,
            "verifiedName": verified_name
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
