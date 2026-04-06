import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Linear (Project Management)

    Checks: Whether the Linear API is responsive and returning valid viewer data
    API Source: https://api.linear.app/graphql (viewer query)
    Pass Condition: API returns viewer data with a valid user ID

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "status": str}
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
        gql_data = data.get("data", data)
        viewer = gql_data.get("viewer", {})
        errors = data.get("errors", None)

        has_id = bool(viewer.get("id", ""))
        result = has_id and not errors
        status = "healthy" if result else "unhealthy"
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "status": status
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
