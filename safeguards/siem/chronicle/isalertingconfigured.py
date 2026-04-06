import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for Google Chronicle SIEM

    Checks: Whether detection rules are configured and active
    API Source: /v2/detect/rules
    Pass Condition: At least one detection rule exists and is enabled

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean, "enabledRules": int, "totalRules": int}
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
        rules = data.get("rules", data.get("results", data.get("data", [])))
        if not isinstance(rules, list):
            rules = []

        total = len(rules)
        enabled = [
            r for r in rules
            if r.get("enabled", r.get("liveRuleEnabled", False)) is True
        ]

        result = len(enabled) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isAlertingConfigured": result,
            "enabledRules": len(enabled),
            "totalRules": total
        }

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
