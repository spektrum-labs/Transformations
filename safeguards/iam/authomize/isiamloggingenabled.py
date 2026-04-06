import json
import ast


def transform(input):
    """
    Evaluates isIAMLoggingEnabled for Authomize (IAM)

    Checks: Whether identity activity logs and alerts are captured and monitored
    API Source: GET {baseURL}/v2/policies
    Pass Condition: Policies exist with monitoring or alerting configurations enabled
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

        # ── EVALUATION LOGIC ──
        result = False

        policies = data.get("policies", data.get("data", data.get("items", [])))

        if isinstance(policies, list) and len(policies) > 0:
            # Authomize is an ITDR platform - having active policies means monitoring is enabled
            active_policies = [
                p for p in policies
                if p.get("enabled", p.get("isEnabled", p.get("active", False)))
            ]
            result = len(active_policies) > 0
        elif isinstance(data, dict) and data.get("totalCount", data.get("total", 0)) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"isIAMLoggingEnabled": result}

    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}
