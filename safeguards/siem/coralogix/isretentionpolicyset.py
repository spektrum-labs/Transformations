import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Coralogix

    Checks: Whether data retention quota and policy is configured
    API Source: /api/v1/external/quota
    Pass Condition: Quota is set and retention period is greater than zero

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRetentionPolicySet": boolean, "retentionDays": int}
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
        retention = data.get("retention", data.get("retention_days", data.get("retentionDays", 0)))
        if isinstance(retention, str):
            try:
                retention = int(retention)
            except ValueError:
                retention = 0

        result = retention > 0
        # -- END EVALUATION LOGIC --

        return {
            "isRetentionPolicySet": result,
            "retentionDays": retention
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
