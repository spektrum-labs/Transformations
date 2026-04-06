import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Kubernetes

    Checks: Whether Kubernetes secrets are configured and managed
    API Source: {baseURL}/api/v1/secrets?limit=100
    Pass Condition: At least one non-default secret exists across namespaces

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "totalSecrets": int, "namespaces": list}
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
        items = data.get("items", [])

        if not isinstance(items, list):
            return {
                "isSecretManagementEnabled": False,
                "totalSecrets": 0,
                "namespaces": [],
                "error": "Unexpected response format"
            }

        # Filter out default service account tokens
        user_secrets = [
            s for s in items
            if isinstance(s, dict)
            and s.get("type", "") != "kubernetes.io/service-account-token"
        ]

        namespaces = list(set(
            s.get("metadata", {}).get("namespace", "unknown")
            for s in user_secrets
            if isinstance(s, dict)
        ))

        result = len(user_secrets) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "totalSecrets": len(user_secrets),
            "namespaces": namespaces
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
