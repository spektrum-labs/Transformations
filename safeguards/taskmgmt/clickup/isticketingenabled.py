import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for ClickUp

    Checks: Whether tasks are retrievable from the ClickUp workspace
    API Source: https://api.clickup.com/api/v2/team/{teamId}/task
    Pass Condition: The API returns a tasks array (even if empty)

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
        tasks = data.get("tasks", data.get("data", []))

        if isinstance(tasks, list):
            result = True
            task_count = len(tasks)
        else:
            result = bool(data)
            task_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "taskCount": task_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
