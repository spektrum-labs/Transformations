import json
import ast


def _parse_input(input):
    if isinstance(input, str):
        try:
            parsed = ast.literal_eval(input)
            if isinstance(parsed, dict):
                return parsed
        except:
            pass
        try:
            input = input.replace("'", '"')
            return json.loads(input)
        except:
            raise ValueError("Input string is neither valid Python literal nor JSON")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Verifies roaming clients are deployed for endpoint protection

    Parameters:
        input (dict): Agents data from GET /agents

    Returns:
        dict: {"hasRoamingClientDeployment": boolean, "totalAgents": int, "activeAgents": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        agents = data if isinstance(data, list) else data.get("agents", data.get("roamingClients", []))

        total_agents = len(agents)
        active_agents = 0

        for agent in agents:
            status = agent.get("status", "").lower()
            if status in ("protected", "active", "online"):
                active_agents += 1

        has_deployment = total_agents > 0

        return {
            "hasRoamingClientDeployment": has_deployment,
            "totalAgents": total_agents,
            "activeAgents": active_agents
        }

    except Exception as e:
        return {"hasRoamingClientDeployment": False, "error": str(e)}
