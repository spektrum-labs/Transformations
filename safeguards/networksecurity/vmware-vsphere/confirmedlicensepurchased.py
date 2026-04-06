import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for VMware vSphere (Network Security)"""
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

        # vSphere /api/vcenter/license returns license key information
        licenses = data if isinstance(data, list) else data.get("value", [])
        if isinstance(licenses, list) and len(licenses) > 0:
            for lic in licenses:
                if isinstance(lic, dict):
                    key = lic.get("license", lic.get("licenseKey", ""))
                    if key and isinstance(key, str) and len(key) > 0:
                        result = True
                        break
        elif isinstance(data, dict) and data.get("license", ""):
            result = True

        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
