import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for ManageEngine ServiceDesk Plus Cloud

    Checks: Whether the ServiceDesk Plus Cloud API is responsive and returning valid data
    API Source: https://sdpondemand.manageengine.com/app/{portalId}/api/v3/requests?list_info={"row_count":1}
    Pass Condition: API returns a successful response without error

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
        error = data.get("error", None)
        has_requests = "requests" in data or "results" in data
        response_status = data.get("response_status", {})

        if isinstance(response_status, dict):
            status_code = response_status.get("status_code", 0)
            result = (status_code == 2000 or status_code == 200) and not bool(error)
        else:
            result = has_requests and not bool(error)

        status = "healthy" if result else "unhealthy"
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "status": status
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
