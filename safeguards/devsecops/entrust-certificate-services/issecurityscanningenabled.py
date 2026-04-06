import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for Entrust Certificate Services (PKI / Certificate Management)

    Checks: Whether certificates are being managed and tracked
    API Source: GET https://api.managed.entrust.com/v1/certificates
    Pass Condition: At least one certificate exists in the inventory

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean}
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

        # Check for certificate records indicating active certificate management
        certificates = data.get("certificates", data.get("data", data.get("results", [])))
        if isinstance(certificates, list) and len(certificates) > 0:
            result = True
        elif isinstance(certificates, dict) and certificates.get("serialNumber"):
            result = True
        elif data.get("total", data.get("count", 0)) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isSecurityScanningEnabled": result}
    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
