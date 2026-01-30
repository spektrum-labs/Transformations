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
    Validates at least one network site is configured and protected

    Parameters:
        input (dict): Networks data from GET /networks

    Returns:
        dict: {"hasActiveNetworkSites": boolean, "networkCount": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        networks = data if isinstance(data, list) else data.get("networks", [])

        # Count networks with assigned policies
        active_networks = []
        for network in networks:
            policy_id = network.get("policy_id")
            status = network.get("status", "active").lower()

            if policy_id and status in ("active", "protected"):
                active_networks.append(network)

        has_active = len(active_networks) > 0

        return {
            "hasActiveNetworkSites": has_active,
            "networkCount": len(active_networks),
            "totalNetworks": len(networks)
        }

    except Exception as e:
        return {"hasActiveNetworkSites": False, "error": str(e)}
