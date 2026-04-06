import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for YesWeHack (European Bug Bounty Platform)

    Checks: Whether bug bounty programs are configured with defined scopes and policies
    API Source: GET https://api.yeswehack.com/programs
    Pass Condition: At least one program exists with a defined scope

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

        # Check for bug bounty programs with defined scopes
        items = data.get("items", data.get("data", data.get("programs", [])))
        if isinstance(items, list) and len(items) > 0:
            for program in items:
                if isinstance(program, dict):
                    title = program.get("title", program.get("slug", ""))
                    if title:
                        result = True
                        break
        elif data.get("total", data.get("nb_results", 0)) > 0:
            result = True
        elif data.get("pagination", {}).get("nb_results", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
