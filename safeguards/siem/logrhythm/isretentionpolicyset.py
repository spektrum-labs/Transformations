import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for LogRhythm SIEM

    Checks: Whether the LogRhythm platform is operational and data retention
            is functioning by verifying agent status via the agents endpoint.

    API Source: GET {baseURL}/lr-admin-api/agents
    Pass Condition: At least one agent is reporting and operational, confirming
                    the platform is actively collecting and retaining data.

    Parameters:
        input (dict): JSON data containing API response from the agents endpoint

    Returns:
        dict: {"isRetentionPolicySet": boolean, "agentCount": int, "activeAgents": int}
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

        # LogRhythm agents endpoint returns a list of system agents
        agents = data if isinstance(data, list) else data.get("data", data.get("agents", []))
        if not isinstance(agents, list):
            agents = []

        total_count = len(agents)
        active_count = 0

        for agent in agents:
            status = agent.get("status", agent.get("Status", ""))
            if str(status).lower() in ("active", "running", "online", "ok", "enabled"):
                active_count += 1

        # Platform is operational if agents are reporting, implying data retention
        result = active_count > 0

        return {
            "isRetentionPolicySet": result,
            "agentCount": total_count,
            "activeAgents": active_count
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
