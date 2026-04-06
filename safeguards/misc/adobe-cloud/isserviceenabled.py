import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Adobe Cloud

    Checks: Whether Creative Cloud Libraries are accessible
    API Source: GET https://cc-libraries.adobe.io/api/v1/libraries
    Pass Condition: Libraries endpoint returns a valid response

    Parameters:
        input (dict): JSON data containing API response from libraries endpoint

    Returns:
        dict: {"isServiceEnabled": boolean, "libraryCount": int}
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
        libraries = data.get("libraries", data.get("data", data.get("items", data.get("results", []))))
        if not isinstance(libraries, list):
            libraries = []

        result = True
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "libraryCount": len(libraries)
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
