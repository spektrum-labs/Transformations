import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Maven Repository Manager

    Checks: Whether component scanning and vulnerability analysis is active
    API Source: {baseURL}/service/rest/v1/components?repository=maven-central
    Pass Condition: Components are indexed and available for vulnerability scanning

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "componentCount": int, "repositoryActive": boolean}
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
        items = data.get("items", data.get("components", data.get("data", [])))

        if not isinstance(items, list):
            items = []

        component_count = len(items)
        continuation_token = data.get("continuationToken", None)
        repository_active = component_count > 0 or continuation_token is not None

        result = repository_active
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "componentCount": component_count,
            "repositoryActive": repository_active
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
