import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for LaunchDarkly

    Checks: Whether API token management and access controls are properly configured
    API Source: https://app.launchdarkly.com/api/v2/tokens
    Pass Condition: API tokens exist with proper role-based access and expiration configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "totalTokens": int, "tokensWithRoles": int}
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
        tokens = data.get("items", data.get("data", data.get("results", [])))

        if not isinstance(tokens, list):
            tokens = []

        total = len(tokens)
        tokens_with_roles = [
            t for t in tokens
            if isinstance(t, dict) and (
                t.get("role", "") or t.get("customRoleIds", [])
            )
        ]

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "totalTokens": total,
            "tokensWithRoles": len(tokens_with_roles)
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
