import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for BlinkOps Security Automation

    Checks: Whether automation playbooks are accessible
    API Source: GET https://app.blinkops.com/api/v1/playbooks
    Pass Condition: At least one playbook exists

    Parameters:
        input (dict): JSON data containing API response from playbooks endpoint

    Returns:
        dict: {"isServiceEnabled": boolean, "playbookCount": int}
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
        playbooks = data.get("playbooks", data.get("data", data.get("items", [])))
        if not isinstance(playbooks, list):
            playbooks = []

        result = len(playbooks) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "playbookCount": len(playbooks)
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
