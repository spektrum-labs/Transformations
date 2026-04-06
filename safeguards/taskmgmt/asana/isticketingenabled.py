import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Asana

    Checks: Whether tasks are retrievable from the Asana workspace
    API Source: https://app.asana.com/api/1.0/tasks?workspace={workspaceGid}
    Pass Condition: The API returns a data array (even if empty)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "taskCount": int}
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
        tasks = data.get("data", [])

        if not isinstance(tasks, list):
            return {
                "isTicketingEnabled": False,
                "taskCount": 0,
                "error": "Unexpected tasks response format"
            }

        result = True
        task_count = len(tasks)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "taskCount": task_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
