import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Infoblox Cloud Services Portal (Network Security)"""
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

        # Infoblox /api/infra/v1/services returns active BloxOne services
        results = data.get("results", [])
        if isinstance(results, list) and len(results) > 0:
            for svc in results:
                if isinstance(svc, dict):
                    state = svc.get("service_type", svc.get("state", ""))
                    if state:
                        result = True
                        break
        elif isinstance(data, dict) and data.get("id", ""):
            result = True

        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
