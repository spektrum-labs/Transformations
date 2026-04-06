import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for GitHub (Code Hosting / DevOps)

    Checks: Whether repository rulesets are configured to enforce branch protection
    API Source: GET https://api.github.com/orgs/{org}/rulesets
    Pass Condition: At least one ruleset exists enforcing branch or push protection

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

        # -- EVALUATION LOGIC --
        result = False

        # Check for repository rulesets enforcing branch protection
        rulesets = data if isinstance(data, list) else data.get("data", data.get("rulesets", []))
        if isinstance(rulesets, list) and len(rulesets) > 0:
            for ruleset in rulesets:
                if isinstance(ruleset, dict) and (ruleset.get("id") or ruleset.get("name")):
                    result = True
                    break
        elif isinstance(rulesets, dict) and rulesets.get("id"):
            result = True
        elif data.get("total_count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
