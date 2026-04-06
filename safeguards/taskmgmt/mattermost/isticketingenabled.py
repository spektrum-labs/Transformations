import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Mattermost (Open Source Messaging)

    Checks: Whether posts/messages are searchable via the Mattermost API
    API Source: {baseURL}/api/v4/posts/search
    Pass Condition: API returns search results with posts

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "postCount": int}
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
        order = data.get("order", [])
        posts = data.get("posts", {})

        if isinstance(posts, dict):
            post_count = len(posts)
        elif isinstance(order, list):
            post_count = len(order)
        else:
            post_count = 0

        result = not data.get("error", None) and not data.get("status_code", None) == 401
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "postCount": post_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
