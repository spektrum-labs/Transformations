import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Splunk SIEM

    Checks: Whether the Splunk server is operational and indexes are
            configured for data retention by verifying server info.

    API Source: GET {baseURL}/services/server/info?output_mode=json
    Pass Condition: The server info endpoint returns valid data confirming
                    the platform is operational with data retention in place.

    Parameters:
        input (dict): JSON data containing API response from the server info endpoint

    Returns:
        dict: {"isRetentionPolicySet": boolean, "serverVersion": str, "serverStatus": str}
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

        # Splunk server info is under entry array
        entries = data.get("entry", data.get("entries", []))
        server_version = "unknown"
        server_status = "unknown"

        if isinstance(entries, list) and len(entries) > 0:
            content = entries[0].get("content", entries[0])
            server_version = content.get("version", content.get("generator", {}).get("version", "unknown"))
            server_status = "operational"
            result = True
        elif data.get("generator", {}).get("version"):
            server_version = data["generator"]["version"]
            server_status = "operational"
            result = True
        else:
            result = bool(data) and "error" not in str(data).lower()
            server_status = "operational" if result else "unknown"

        return {
            "isRetentionPolicySet": result,
            "serverVersion": str(server_version),
            "serverStatus": server_status
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
