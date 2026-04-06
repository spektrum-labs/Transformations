import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Kubernetes

    Checks: Whether network policies are enforced across namespaces
    API Source: {baseURL}/apis/networking.k8s.io/v1/networkpolicies
    Pass Condition: At least one network policy exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "totalPolicies": int, "namespaces": list}
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
                "isPipelineSecured": False,
                "totalPolicies": 0,
                "namespaces": [],
                "error": "Unexpected response format"
            }

        total = len(items)
        namespaces = list(set(
            item.get("metadata", {}).get("namespace", "unknown")
            for item in items
            if isinstance(item, dict)
        ))

        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "totalPolicies": total,
            "namespaces": namespaces
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
