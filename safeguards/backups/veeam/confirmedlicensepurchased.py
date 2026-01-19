# confirmedlicensepurchased.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if the license has been purchased for Veeam Service Provider Console.

    Parameters:
        input (dict): The JSON data from Veeam license endpoint.

    Returns:
        dict: A dictionary summarizing the license purchase information.
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
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        default_value = True if data is not None else False

        license_purchased = data.get('licensePurchased', default_value)

        if not license_purchased:
            # Check for license status indicators
            license_status = data.get("status", data.get("licenseStatus", ""))
            if license_status and str(license_status).lower() in ["active", "valid", "licensed"]:
                license_purchased = True

            # Check for license type
            license_type = data.get("type", data.get("licenseType", ""))
            if license_type:
                license_purchased = True

            # Check for expiration date (indicates valid license)
            expiration = data.get("expirationDate", data.get("expiration", ""))
            if expiration:
                license_purchased = True

            # Check for licensed instances/sockets
            instances = data.get("instancesUsed", data.get("licensedInstances", 0))
            if instances and instances > 0:
                license_purchased = True

            # Check for any jobs (indicates active subscription)
            jobs = data.get("jobs", data.get("items", []))
            if isinstance(jobs, list) and len(jobs) > 0:
                license_purchased = True

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
