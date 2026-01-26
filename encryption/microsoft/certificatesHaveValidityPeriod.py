# certificatesHaveValidityPeriod.py
# Azure Key Vault - DP-7.1: Certificate Management - Maximum Validity Period
# Azure Policy: 0a075868-4c26-42ef-914c-5bc007359560

import json
import ast

def transform(input):
    """
    Checks whether all certificates have validity periods within the maximum allowed (397 days).
    Aligns with Azure Policy: 0a075868-4c26-42ef-914c-5bc007359560
    Default max validity: 397 days (CA/Browser Forum baseline requirement)
    
    API Endpoint (Data Plane):
        GET https://{vaultName}.vault.azure.net/certificates?api-version=7.4
        Token scope: https://vault.azure.net/.default
    
    Transformation Logic:
        True if all certificates have validity <= 397 days (or no certificates exist)
        False if any certificate exceeds maximum validity period
    
    Returns: {"certificatesHaveValidityPeriod": bool}
    """
    MAX_VALIDITY_DAYS = 397  # CA/Browser Forum baseline requirement
    SECONDS_PER_DAY = 86400

    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        data = data.get("data", data)

        # Get list of certificates
        certificates = data.get("value", [])

        # If no certificates exist, consider compliant
        if len(certificates) == 0:
            return {"certificatesHaveValidityPeriod": True}

        # Check each certificate validity period
        for cert in certificates:
            attributes = cert.get("attributes", {})
            nbf = attributes.get("nbf")  # Not Before (Unix timestamp)
            exp = attributes.get("exp")  # Expiration (Unix timestamp)

            if nbf is None or exp is None:
                return {"certificatesHaveValidityPeriod": False}

            # Calculate validity period in days
            validity_days = (exp - nbf) / SECONDS_PER_DAY

            if validity_days > MAX_VALIDITY_DAYS:
                return {"certificatesHaveValidityPeriod": False}

        return {"certificatesHaveValidityPeriod": True}

    except json.JSONDecodeError:
        return {"certificatesHaveValidityPeriod": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"certificatesHaveValidityPeriod": False, "error": str(e)}
