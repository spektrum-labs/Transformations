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
    Checks if Blumira Agent is deployed on at least one endpoint

    Parameters:
        input (dict): Agents API response

    Returns:
        dict: {"isAgentDeployed": boolean, "deployedCount": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        agents = data.get("agents", [])
        deployed_count = data.get("currentDeployedCount", len(agents))

        is_deployed = deployed_count > 0

        return {
            "isAgentDeployed": is_deployed,
            "deployedCount": deployed_count
        }

    except Exception as e:
        return {"isAgentDeployed": False, "error": str(e)}
