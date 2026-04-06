import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Linear (Project Management)

    Checks: Whether issues are retrievable from Linear
    API Source: https://api.linear.app/graphql (issues query)
    Pass Condition: API returns a list of issue nodes without errors

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "issueCount": int}
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
        issues_conn = gql_data.get("issues", {})
        nodes = issues_conn.get("nodes", [])
        errors = data.get("errors", None)

        if not isinstance(nodes, list):
            return {
                "isTicketingEnabled": False,
                "issueCount": 0,
                "error": "Unexpected response format"
            }

        issue_count = len(nodes)
        result = issue_count >= 0 and not errors
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "issueCount": issue_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
