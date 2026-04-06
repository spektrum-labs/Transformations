import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Jira Data Center (On-Premise)

    Checks: Whether issues are searchable via the Jira REST API
    API Source: {baseURL}/rest/api/2/search?jql=order+by+created+DESC&maxResults=25
    Pass Condition: API returns search results with issues array

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "issueCount": int, "totalIssues": int}
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
        issues = data.get("issues", [])
        total = data.get("total", 0)

        if not isinstance(issues, list):
            return {
                "isTicketingEnabled": False,
                "issueCount": 0,
                "totalIssues": 0,
                "error": "Unexpected response format"
            }

        issue_count = len(issues)
        result = issue_count >= 0 and not data.get("errorMessages", None)
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "issueCount": issue_count,
            "totalIssues": total
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
