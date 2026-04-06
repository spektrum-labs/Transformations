import json
import ast


def transform(input):
    """
    Evaluates isWorkflowConfigured for WhatsApp Business

    Checks: Whether message templates are configured in the WhatsApp Business Account
    API Source: https://graph.facebook.com/v23.0/{businessAccountId}/message_templates
    Pass Condition: At least 1 message template exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isWorkflowConfigured": boolean, "templateCount": int}
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
        templates = data.get("data", data.get("message_templates", []))

        if not isinstance(templates, list):
            return {
                "isWorkflowConfigured": False,
                "templateCount": 0,
                "error": "Unexpected templates response format"
            }

        count = len(templates)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isWorkflowConfigured": result,
            "templateCount": count
        }

    except Exception as e:
        return {"isWorkflowConfigured": False, "error": str(e)}
