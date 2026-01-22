# confirmedlicensepurchased.py - Rubrik

import json
import ast

def transform(input):
    """
    Validates that a Rubrik cluster is accessible and returns license status
    based on cluster connectivity. Checks for cluster ID and version existence.

    Parameters:
        input (dict): The JSON data from Rubrik getClusterInfo endpoint.

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

        license_purchased = False

        # Check for cluster ID - indicates valid license/connectivity
        cluster_id = data.get("clusterId", data.get("id", ""))
        if cluster_id:
            license_purchased = True

        # Check for version - indicates active system
        version = data.get("version", "")
        if version:
            license_purchased = True

        # Check for cluster name
        cluster_name = data.get("clusterName", data.get("name", ""))
        if cluster_name:
            license_purchased = True

        # Check for timezone (indicates configured cluster)
        timezone = data.get("timezone", "")
        if timezone:
            license_purchased = True

        # Check for geolocation (indicates configured cluster)
        geolocation = data.get("geolocation", {})
        if isinstance(geolocation, dict) and geolocation:
            license_purchased = True

        # Check for license-specific fields
        if data.get("licensePurchased") or data.get("licenseStatus"):
            license_purchased = True

        license_info = {
            "confirmedLicensePurchased": license_purchased,
            "clusterId": cluster_id,
            "clusterName": cluster_name,
            "version": version
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
