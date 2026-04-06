import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Maven Repository Manager

    Checks: Whether content selectors and security policies are configured
    API Source: {baseURL}/service/rest/v1/security/content-selectors
    Pass Condition: At least one content selector exists for access control

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "selectorCount": int, "selectors": list}
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
        selectors = data if isinstance(data, list) else data.get("data", data.get("items", data.get("results", [])))

        if not isinstance(selectors, list):
            return {
                "isPipelineSecured": False,
                "selectorCount": 0,
                "selectors": [],
                "error": "Unexpected response format"
            }

        selector_names = [
            s.get("name", "unknown")
            for s in selectors
            if isinstance(s, dict)
        ]

        result = len(selector_names) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "selectorCount": len(selector_names),
            "selectors": selector_names
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
