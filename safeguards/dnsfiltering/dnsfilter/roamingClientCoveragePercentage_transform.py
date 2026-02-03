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
    Calculates percentage of protected roaming clients

    Parameters:
        input (dict): Agents data from GET /agents

    Returns:
        dict: {"roamingClientCoveragePercentage": boolean, "coverage": float}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        agents = data if isinstance(data, list) else data.get("agents", data.get("roamingClients", []))

        total_agents = len(agents)

        if total_agents == 0:
            return {
                "roamingClientCoveragePercentage": False,
                "coverage": 0,
                "error": "No roaming clients deployed"
            }

        protected_agents = 0
        for agent in agents:
            status = agent.get("status", "").lower()
            if status in ("protected", "active", "online"):
                protected_agents += 1

        coverage = (protected_agents / total_agents) * 100

        # Pass if coverage >= 95%
        meets_threshold = coverage >= 95

        return {
            "roamingClientCoveragePercentage": meets_threshold,
            "coverage": round(coverage, 2),
            "totalAgents": total_agents,
            "protectedAgents": protected_agents
        }

    except Exception as e:
        return {"roamingClientCoveragePercentage": False, "error": str(e)}
