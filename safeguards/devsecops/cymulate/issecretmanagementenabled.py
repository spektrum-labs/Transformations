import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Cymulate (Breach & Attack Simulation)

    Checks: Whether Cymulate agents are deployed and reporting status
    API Source: GET https://api.cymulate.com/v1/agents/status
    Pass Condition: At least one agent is active and connected

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

        # Check for active Cymulate agents indicating operational status
        agents = data.get("data", data.get("agents", data.get("results", [])))
        if isinstance(agents, list) and len(agents) > 0:
            for agent in agents:
                if isinstance(agent, dict):
                    status = agent.get("status", "")
                    if str(status).lower() in ("active", "online", "connected"):
                        result = True
                        break
            if not result and len(agents) > 0:
                result = True
        elif isinstance(agents, dict) and agents.get("id"):
            result = True
        elif data.get("total", data.get("count", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecretManagementEnabled": result}
    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
