import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Nozomi Networks

    Checks: Whether security assertions and monitoring policies are configured
    API Source: {baseURL}/api/open/query/do?query=assertions
    Pass Condition: At least one security assertion or monitoring rule exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "assertionCount": int, "activeAssertions": int}
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
        assertions = data.get("result", data.get("data", data.get("items", [])))

        if isinstance(assertions, list):
            total = len(assertions)
            active = [
                a for a in assertions
                if isinstance(a, dict) and a.get("enabled", True)
            ]
        else:
            total = 0
            active = []

        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "assertionCount": total,
            "activeAssertions": len(active)
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
