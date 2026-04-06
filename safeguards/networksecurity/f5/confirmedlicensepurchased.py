import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for F5 (Network Security)"""
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

        # F5 /mgmt/tm/sys/license returns entries with registration keys
        entries = data.get("entries", {})
        if isinstance(entries, dict) and len(entries) > 0:
            result = True
        else:
            # Fallback: check for registrationKey field
            reg_key = data.get("registrationKey", "")
            if reg_key and isinstance(reg_key, str) and len(reg_key) > 0:
                result = True

        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
