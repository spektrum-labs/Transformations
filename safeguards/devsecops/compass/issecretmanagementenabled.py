import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Atlassian Compass (Developer Portal)

    Checks: Whether components are registered and managed in Compass
    API Source: GET {baseURL}/v1/components
    Pass Condition: At least one component is registered with active lifecycle management

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

        # Check for components indicating active service catalog management
        components = data.get("values", data.get("data", []))
        if isinstance(components, list) and len(components) > 0:
            result = True
        elif data.get("total", 0) > 0:
            result = True
        elif data.get("size", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
