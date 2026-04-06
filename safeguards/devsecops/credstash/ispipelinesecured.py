import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for CredStash (AWS Secrets Management)

    Checks: Whether access policies and KMS encryption are configured
    API Source: GET {baseURL}/policies
    Pass Condition: At least one access policy or KMS key configuration exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean}
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
        result = False

        # Check for KMS and IAM policies securing the credential store
        policies = data.get("policies", data.get("data", []))
        if isinstance(policies, list) and len(policies) > 0:
            result = True
        elif isinstance(policies, dict) and len(policies) > 0:
            result = True
        elif data.get("kmsKey") or data.get("kms_key_id"):
            result = True
        elif data.get("encryption") and data.get("encryption") != "none":
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
