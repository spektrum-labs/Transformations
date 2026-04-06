import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for TeamCity (JetBrains CI/CD Server)

    Checks: Whether build agents are configured for secure pipeline execution
    API Source: GET {baseURL}/app/rest/agents?locator=authorized:true
    Pass Condition: At least one authorized agent exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean}
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

        # Check for authorized build agents
        agents = data.get("agent", data.get("agents", []))
        if isinstance(agents, list) and len(agents) > 0:
            result = True
        elif data.get("count", 0) > 0:
            result = True
        elif data.get("href") and data.get("count") is not None:
            result = data.get("count", 0) > 0
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
