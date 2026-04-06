import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Atlassian Compass (Developer Portal)

    Checks: Whether scorecards are configured to enforce component health standards
    API Source: GET {baseURL}/v1/scorecards
    Pass Condition: At least one scorecard is defined enforcing component compliance

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

        # Check for scorecards that enforce pipeline and component security policies
        scorecards = data.get("values", data.get("data", []))
        if isinstance(scorecards, list) and len(scorecards) > 0:
            for scorecard in scorecards:
                if isinstance(scorecard, dict) and (scorecard.get("id") or scorecard.get("name")):
                    result = True
                    break
        elif data.get("total", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
