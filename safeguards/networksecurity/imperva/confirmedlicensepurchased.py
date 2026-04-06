import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Imperva (Network Security)"""
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

        # Imperva /api/prov/v1/accounts returns account info with subscription details
        account = data.get("account", data)
        if isinstance(account, dict):
            plan = account.get("planName", account.get("plan_name", ""))
            if plan and isinstance(plan, str) and len(plan) > 0:
                result = True
            else:
                status = account.get("status", "")
                if status and isinstance(status, str) and status.lower() in ("active", "valid"):
                    result = True

        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
