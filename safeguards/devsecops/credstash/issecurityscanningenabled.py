import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for CredStash (AWS Secrets Management)

    Checks: Whether credentials are stored and managed in CredStash
    API Source: GET {baseURL}/credentials
    Pass Condition: At least one credential entry exists in the store

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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

        # Check for credential entries in the CredStash store
        credentials = data.get("credentials", data.get("keys", data.get("data", [])))
        if isinstance(credentials, list) and len(credentials) > 0:
            result = True
        elif isinstance(credentials, dict) and len(credentials) > 0:
            result = True
        elif data.get("count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
