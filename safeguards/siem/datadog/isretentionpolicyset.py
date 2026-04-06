import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Datadog

    Checks: Whether log archive and retention configuration is set
    API Source: /api/v2/logs/config/archives
    Pass Condition: At least one log archive is configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRetentionPolicySet": boolean, "archiveCount": int}
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
        archives = data.get("data", data.get("archives", []))
        if not isinstance(archives, list):
            archives = []

        count = len(archives)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isRetentionPolicySet": result,
            "archiveCount": count
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
