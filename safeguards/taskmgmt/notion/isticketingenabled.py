import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Notion (All-in-One Workspace)

    Checks: Whether databases are searchable via the Notion API
    API Source: https://api.notion.com/v1/search
    Pass Condition: API returns search results with database objects

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "databaseCount": int}
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
        results = data.get("results", [])

        if not isinstance(results, list):
            return {
                "isTicketingEnabled": False,
                "databaseCount": 0,
                "error": "Unexpected response format"
            }

        databases = [r for r in results if r.get("object") == "database"]
        database_count = len(databases)
        result = database_count >= 0 and not data.get("code", None)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "databaseCount": database_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
