import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for UKG HR Service Delivery.

    Checks: Whether the API application has correct scopes by verifying
            document types are accessible.
    API Source: GET {baseURL}/api/v2/client/document_types
    Pass Condition: API returns document type data without authentication errors

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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
        error = data.get("error", data.get("errors", None))
        status_code = data.get("status_code", data.get("statusCode", 200))

        if error:
            result = False
        elif isinstance(status_code, int) and status_code in (401, 403):
            result = False
        elif isinstance(data, dict) and len(data) > 0:
            result = True
        else:
            result = False
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}

    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
