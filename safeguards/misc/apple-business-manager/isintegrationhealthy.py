import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Apple Business Manager

    Checks: Whether the ABM API is reachable and OAuth/JWT authentication succeeds
    API Source: GET https://mdmenrollment.apple.com/v1/mdmServers
    Pass Condition: A successful (non-error) response is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean}
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
        status_code = data.get("statusCode", data.get("status_code", data.get("code", 200)))

        if error:
            result = False
        elif isinstance(status_code, int) and status_code >= 400:
            result = False
        else:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isIntegrationHealthy": result}

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
