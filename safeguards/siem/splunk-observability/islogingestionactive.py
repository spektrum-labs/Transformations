import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Splunk Observability Cloud

    Checks: Whether Splunk Observability has active integrations configured
            by verifying the integrations endpoint returns enabled data sources.

    API Source: GET {baseURL}/v2/integration?limit=50
    Pass Condition: At least one integration exists and is enabled, confirming
                    data is being ingested into Splunk Observability Cloud.

    Parameters:
        input (dict): JSON data containing API response from the integration endpoint

    Returns:
        dict: {"isLogIngestionActive": boolean, "activeIntegrationCount": int, "totalIntegrationCount": int}
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

        # Standard response unwrapping chain
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Splunk Observability returns integrations as results array
        integrations = data if isinstance(data, list) else data.get("results", data.get("data", []))
        if not isinstance(integrations, list):
            integrations = []

        total_count = len(integrations)
        active_count = 0

        for integration in integrations:
            enabled = integration.get("enabled", integration.get("isEnabled", True))
            if enabled is not False:
                active_count += 1

        result = active_count > 0

        return {
            "isLogIngestionActive": result,
            "activeIntegrationCount": active_count,
            "totalIntegrationCount": total_count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
