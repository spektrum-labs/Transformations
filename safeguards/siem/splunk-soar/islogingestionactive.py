import json
import ast


def transform(input):
    """
    Evaluates isLogIngestionActive for Splunk SOAR

    Checks: Whether Splunk SOAR has assets configured for event ingestion
            by verifying the asset endpoint returns at least one active asset.

    API Source: GET {baseURL}/rest/asset?page_size=50
    Pass Condition: At least one asset is configured, confirming that event
                    sources are connected and ingestion is active.

    Parameters:
        input (dict): JSON data containing API response from the asset endpoint

    Returns:
        dict: {"isLogIngestionActive": boolean, "activeAssetCount": int, "totalAssetCount": int}
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

        # Splunk SOAR returns assets under data array
        assets = data if isinstance(data, list) else data.get("data", data.get("assets", []))
        if not isinstance(assets, list):
            # Check count field
            count = data.get("count", data.get("num_found", 0))
            if isinstance(count, (int, float)) and count > 0:
                return {
                    "isLogIngestionActive": True,
                    "activeAssetCount": int(count),
                    "totalAssetCount": int(count)
                }
            assets = []

        total_count = len(assets)
        active_count = 0

        for asset in assets:
            disabled = asset.get("disabled", asset.get("is_disabled", False))
            if not disabled:
                active_count += 1

        result = active_count > 0

        return {
            "isLogIngestionActive": result,
            "activeAssetCount": active_count,
            "totalAssetCount": total_count
        }

    except Exception as e:
        return {"isLogIngestionActive": False, "error": str(e)}
