def transform(input):
    """
    Checks Liongard agent deployment status across environments.
    Liongard agents can be installed in the Cloud or On-Premises
    and are responsible for running inspections.

    Parameters:
        input (dict): The JSON data containing Liongard agents response

    Returns:
        dict: A dictionary with the isAgentDeployed evaluation result
    """

    criteria_key = "isAgentDeployed"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']

        # Get agents array
        agents = input.get("data", input.get("agents", input.get("items", [])))
        if isinstance(input, list):
            agents = input

        total_count = len(agents) if isinstance(agents, list) else 0
        active_count = 0
        online_count = 0

        for agent in agents if isinstance(agents, list) else []:
            # Check agent status
            status = str(agent.get("status", agent.get("agentStatus", ""))).lower()
            is_active = status in ["active", "online", "connected", "healthy", "running"]

            # Check connection status
            connection = str(agent.get("connectionStatus", agent.get("connection", ""))).lower()
            is_connected = connection in ["connected", "online", "active"]

            # Check last seen/heartbeat
            last_seen = agent.get("lastSeen", agent.get("lastHeartbeat", agent.get("lastContact")))
            has_recent_contact = bool(last_seen)

            if is_active or is_connected:
                active_count += 1
                if is_connected or has_recent_contact:
                    online_count += 1

        # Calculate percentage
        if total_count > 0:
            active_percentage = (active_count / total_count) * 100
            online_percentage = (online_count / total_count) * 100
        else:
            active_percentage = 0.0
            online_percentage = 0.0

        # Consider deployed if we have active agents
        is_deployed = active_count > 0 and active_percentage >= 80.0

        return {
            criteria_key: is_deployed,
            "totalAgents": total_count,
            "activeAgents": active_count,
            "onlineAgents": online_count,
            "activePercentage": round(active_percentage, 2),
            "onlinePercentage": round(online_percentage, 2)
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
