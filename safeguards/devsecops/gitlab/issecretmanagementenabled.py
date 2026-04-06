import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for GitLab

    Checks: Whether CI/CD variables are configured with masking and protection enabled
    API Source: {baseURL}/api/v4/projects/{projectId}/variables
    Pass Condition: At least one CI/CD variable exists with masked or protected settings

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "totalVariables": int, "maskedCount": int, "protectedCount": int}
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
        variables = data if isinstance(data, list) else data.get("data", data.get("items", data.get("results", [])))

        if not isinstance(variables, list):
            return {
                "isSecretManagementEnabled": False,
                "totalVariables": 0,
                "maskedCount": 0,
                "protectedCount": 0,
                "error": "Unexpected response format"
            }

        total = len(variables)
        masked = [v for v in variables if isinstance(v, dict) and v.get("masked", False)]
        protected = [v for v in variables if isinstance(v, dict) and v.get("protected", False)]

        result = total > 0 and (len(masked) > 0 or len(protected) > 0)
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "totalVariables": total,
            "maskedCount": len(masked),
            "protectedCount": len(protected)
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
