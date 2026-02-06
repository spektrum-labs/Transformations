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
            raise ValueError("Invalid input format")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Calculates endpoint coverage percentage

    Coverage = (Online Agents / Max Deployable Agents) * 100
    Pass threshold: >= 95%

    Parameters:
        input (dict): Agents API response

    Returns:
        dict: {"requiredCoveragePercentage": boolean, "coverage": float}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        agents = data.get("agents", [])
        max_deployable = data.get("maxDeployableAgents", 0)

        # Count online agents
        online_agents = sum(1 for a in agents if a.get("status", "").lower() == "online")

        if max_deployable == 0:
            return {
                "requiredCoveragePercentage": False,
                "coverage": 0,
                "error": "No agents licensed"
            }

        coverage = (online_agents / max_deployable) * 100

        return {
            "requiredCoveragePercentage": coverage >= 95,
            "coverage": round(coverage, 2),
            "onlineAgents": online_agents,
            "maxDeployable": max_deployable
        }

    except Exception as e:
        return {"requiredCoveragePercentage": False, "error": str(e)}
