import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Beeceptor (API Mocking)

    Checks: Whether mocking rules are configured to enforce security policies on API endpoints
    API Source: GET https://app.beeceptor.com/api/v2/endpoints/{endpointName}/rules
    Pass Condition: At least one mocking rule exists with defined request matching conditions

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean}
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

        # ── EVALUATION LOGIC ──
        result = False

        # Check for mocking rules that enforce request validation
        rules = data if isinstance(data, list) else data.get("rules", data.get("data", []))
        if isinstance(rules, list) and len(rules) > 0:
            for rule in rules:
                if isinstance(rule, dict) and (rule.get("path") or rule.get("method") or rule.get("pattern")):
                    result = True
                    break
        # ── END EVALUATION LOGIC ──

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
