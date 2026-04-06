import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for JetBrains Space

    Checks: Whether project parameters and secrets are configured securely
    API Source: {baseURL}/api/http/projects/params
    Pass Condition: At least one project parameter exists with secret type

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "totalParams": int, "secretParams": int}
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
        params = data.get("data", data.get("items", data.get("results", [])))

        if not isinstance(params, list):
            params = []

        total = len(params)
        secrets = [
            p for p in params
            if isinstance(p, dict) and (
                p.get("type", "").lower() == "secret"
                or p.get("secret", False)
                or p.get("masked", False)
            )
        ]

        result = total > 0 and len(secrets) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "totalParams": total,
            "secretParams": len(secrets)
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
