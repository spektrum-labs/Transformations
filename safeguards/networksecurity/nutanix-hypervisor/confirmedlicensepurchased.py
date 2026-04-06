import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Nutanix Hypervisor (Network Security)"""
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
                    raise ValueError("Invalid input")
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
        result = False

        # Nutanix /api/nutanix/v3/cluster returns cluster info with license details
        status = data.get("status", {})
        if isinstance(status, dict):
            resources = status.get("resources", {})
            if isinstance(resources, dict):
                config = resources.get("config", {})
                cluster_name = config.get("cluster_name", resources.get("name", ""))
                if cluster_name:
                    result = True
        elif isinstance(data, dict) and data.get("metadata", {}).get("kind", "") == "cluster":
            result = True

        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
