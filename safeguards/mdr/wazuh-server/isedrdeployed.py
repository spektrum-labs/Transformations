import json
import ast


def transform(input):
    """
    Evaluates isEDRDeployed for Wazuh Server MDR

    Checks: Whether Wazuh agents are deployed by verifying the agents endpoint
            returns at least one active agent with a recent keepAlive timestamp.

    API Source: GET {baseURL}/agents?limit=50&select=id,name,status,os.name,os.version,lastKeepAlive
    Pass Condition: At least one agent exists with an active status, confirming
                    that endpoint detection agents are deployed and reporting.

    Parameters:
        input (dict): JSON data containing API response from the agents endpoint

    Returns:
        dict: {"isEDRDeployed": boolean, "activeAgentCount": int, "totalAgentCount": int}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Wazuh returns agents under data.affected_items or data.items
        agent_data = data.get("data", data)
        agents = agent_data.get("affected_items", agent_data.get("items", []))
        if not isinstance(agents, list):
            agents = []

        # Also check total_affected_items for count
        total_affected = agent_data.get("total_affected_items", agent_data.get("totalItems", len(agents)))

        total_count = len(agents) if agents else int(total_affected) if total_affected else 0
        active_count = 0

        for agent in agents:
            status = agent.get("status", "")
            agent_id = agent.get("id", "")

            # Skip the manager agent (id=000) for endpoint deployment check
            if str(agent_id) == "000":
                total_count = max(0, total_count - 1)
                continue

            if str(status).lower() in ("active", "connected"):
                active_count += 1

        result = active_count > 0

        return {
            "isEDRDeployed": result,
            "activeAgentCount": active_count,
            "totalAgentCount": total_count
        }

    except Exception as e:
        return {"isEDRDeployed": False, "error": str(e)}
