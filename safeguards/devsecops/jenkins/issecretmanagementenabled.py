import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Jenkins

    Checks: Whether the Jenkins credentials store is configured with managed secrets
    API Source: {baseURL}/credentials/api/json?depth=1
    Pass Condition: At least one credentials store with stored credentials exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "storeCount": int, "credentialCount": int}
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
        stores = data.get("stores", {})
        store_count = 0
        credential_count = 0

        if isinstance(stores, dict):
            store_count = len(stores)
            for store_key, store_val in stores.items():
                if isinstance(store_val, dict):
                    domains = store_val.get("domains", {})
                    if isinstance(domains, dict):
                        for domain_key, domain_val in domains.items():
                            if isinstance(domain_val, dict):
                                creds = domain_val.get("credentials", [])
                                if isinstance(creds, list):
                                    credential_count += len(creds)

        result = store_count > 0 and credential_count > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "storeCount": store_count,
            "credentialCount": credential_count
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
