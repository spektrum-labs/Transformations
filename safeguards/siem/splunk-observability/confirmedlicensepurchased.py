import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Splunk Observability Cloud

    Checks: Whether the Splunk Observability Cloud organization is active
            by checking the organization endpoint for a valid response.

    API Source: GET {baseURL}/v2/organization
    Pass Condition: The organization endpoint returns valid org data,
                    confirming an active subscription exists.

    Parameters:
        input (dict): JSON data containing API response from the organization endpoint

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "orgName": str}
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

        # Splunk Observability organization endpoint returns org details
        org_name = data.get("name", data.get("organizationName", ""))
        org_id = data.get("id", data.get("organizationId", ""))

        # A valid response with organization data confirms an active license
        result = bool(org_id or org_name) and "error" not in str(data).lower()

        return {
            "confirmedLicensePurchased": result,
            "orgName": str(org_name) if org_name else "unknown",
            "orgId": str(org_id) if org_id else "unknown"
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
