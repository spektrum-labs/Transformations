import json
import ast


def transform(input):
    """
    Evaluates isDataClassified for Airlock Digital

    Checks: Whether at least one agent is enrolled and reporting
    API Source: https://{server}:3129/api/v1/agents
    Pass Condition: At least one agent exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isDataClassified": boolean, "activeAgents": int, "totalAgents": int}
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
        agents = data.get("agents", data.get("data", {}).get("agents", data.get("items", [])))

        if not isinstance(agents, list):
            agents = [agents] if agents else []

        total = len(agents)
        active = [a for a in agents if a.get("status", "active").lower() in {"active", "online"}] if agents else []

        result = len(active) >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isDataClassified": result,
            "activeAgents": len(active),
            "totalAgents": total
        }

    except Exception as e:
        return {"isDataClassified": False, "error": str(e)}
