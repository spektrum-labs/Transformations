import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for Jira Data Center (On-Premise)

    Checks: Whether the Jira Data Center instance is responsive and reporting server info
    API Source: {baseURL}/rest/api/2/serverInfo
    Pass Condition: API returns valid server info with version and baseUrl

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "serverTitle": str, "status": str}
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
        version = data.get("version", "")
        base_url = data.get("baseUrl", "")
        server_title = data.get("serverTitle", "unknown")

        result = bool(version) and bool(base_url)
        status = "healthy" if result else "unhealthy"
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "serverTitle": server_title,
            "status": status
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
