import json
import ast


def transform(input):
    """
    Evaluates isRetentionPolicySet for Elasticsearch

    Checks: Whether Index Lifecycle Management (ILM) policies are configured
    API Source: /_ilm/policy
    Pass Condition: At least one ILM policy exists with a delete phase configured

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isRetentionPolicySet": boolean, "policyCount": int, "policiesWithRetention": int}
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
        if not isinstance(data, dict):
            return {
                "isRetentionPolicySet": False,
                "policyCount": 0,
                "policiesWithRetention": 0,
                "error": "Unexpected ILM response format"
            }

        policies = data
        policy_count = len(policies)
        with_retention = 0

        for name, policy_def in policies.items():
            policy = policy_def.get("policy", {})
            phases = policy.get("phases", {})
            if "delete" in phases or "warm" in phases or "cold" in phases:
                with_retention = with_retention + 1

        result = policy_count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isRetentionPolicySet": result,
            "policyCount": policy_count,
            "policiesWithRetention": with_retention
        }

    except Exception as e:
        return {"isRetentionPolicySet": False, "error": str(e)}
