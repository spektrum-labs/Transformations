import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for WhoisXML API.

    Checks: Whether the API key is valid by verifying the account balance
            endpoint returns data without authentication errors.
    API Source: GET https://user.whoisxmlapi.com/user-service/account-balance
    Pass Condition: Account balance is retrievable without API key errors

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
        error = data.get("error", data.get("ErrorMessage", None))
        status_code = data.get("status_code", data.get("statusCode", 200))

        if error:
            error_str = str(error).lower()
            if "api key" in error_str or "authentication" in error_str or "unauthorized" in error_str:
                result = False
            else:
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
