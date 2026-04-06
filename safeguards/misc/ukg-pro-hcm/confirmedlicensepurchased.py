import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for UKG Pro HCM.

    Checks: Active UKG Pro subscription by verifying successful Basic auth
            and company data retrieval from the personnel API.
    API Source: GET {baseURL}/api/personnel/v1/companies
    Pass Condition: API returns company data without authentication errors

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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
        companies = data.get("companies", data.get("data", data.get("results", [])))
        error = data.get("error", data.get("errors", None))

        if error:
            result = False
            status = "error"
        elif isinstance(companies, list) and len(companies) > 0:
            result = True
            status = "active"
        elif isinstance(data, dict) and len(data) > 0 and not error:
            result = True
            status = "active"
        else:
            result = False
            status = "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": "unknown",
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
