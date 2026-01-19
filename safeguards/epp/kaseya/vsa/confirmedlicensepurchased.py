import json
import ast


def transform(input):
    """
    Evaluates whether a Kaseya VSA license has been purchased.
    Checks the environment/license response for valid license indicators.

    Parameters:
        input (dict): The JSON data from Kaseya getEnvironment endpoint.

    Returns:
        dict: A dictionary indicating if a license has been purchased.
    """
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

        # Navigate through response wrappers
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        data = data.get("Data", data)

        # Check for explicit license purchased field
        if "licensePurchased" in data:
            return {"confirmedLicensePurchased": bool(data["licensePurchased"])}

        # Check for license status indicators
        license_status = data.get("licenseStatus", data.get("status", "")).lower()
        if license_status in ["active", "valid", "licensed", "enabled"]:
            return {"confirmedLicensePurchased": True}

        # Check for environment ID and version as indicators of valid license
        environment_id = data.get("id", data.get("environmentId", ""))
        version = data.get("version", "")
        environment_name = data.get("name", data.get("environmentName", ""))

        if environment_id and version:
            return {"confirmedLicensePurchased": True}

        # Check for license type presence
        license_type = data.get("licenseType", data.get("type", ""))
        if license_type:
            return {"confirmedLicensePurchased": True}

        # Check for expiration date (presence indicates license exists)
        expiration = data.get("expirationDate", data.get("licenseExpiration", ""))
        if expiration:
            return {"confirmedLicensePurchased": True}

        # Check for licensed features or modules
        features = data.get("features", data.get("licensedFeatures", data.get("modules", [])))
        if features and len(features) > 0:
            return {"confirmedLicensePurchased": True}

        # Default to False if no license indicators found
        return {"confirmedLicensePurchased": False}

    except json.JSONDecodeError:
        return {"confirmedLicensePurchased": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
