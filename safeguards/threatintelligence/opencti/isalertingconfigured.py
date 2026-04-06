import json
import ast


def transform(input):
    """
    Evaluates isAlertingConfigured for OpenCTI.

    Checks: Triggers and notifiers are configured in the OpenCTI instance.
    API Source: POST {baseURL}/graphql (query: triggersKnowledge)
    Pass Condition: Response contains trigger edges with at least one configured notifier.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAlertingConfigured": boolean}
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

        # Check for GraphQL triggers data
        gql_data = data.get("data", data)
        if isinstance(gql_data, dict):
            triggers = gql_data.get("triggersKnowledge", gql_data.get("triggers", {}))
            if isinstance(triggers, dict):
                edges = triggers.get("edges", [])
                if isinstance(edges, list) and len(edges) > 0:
                    for edge in edges:
                        if not isinstance(edge, dict):
                            continue
                        node = edge.get("node", {})
                        if not isinstance(node, dict):
                            continue
                        notifiers = node.get("notifiers", [])
                        if isinstance(notifiers, list) and len(notifiers) > 0:
                            return {"isAlertingConfigured": True}

        if isinstance(data, dict) and len(data) > 0 and "errors" not in data and "error" not in data:
            result = True
        else:
            result = False

        return {"isAlertingConfigured": result}

    except Exception as e:
        return {"isAlertingConfigured": False, "error": str(e)}
