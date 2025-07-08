# calculaterisks.py

import json

def transform(input):
    """
    Calculates the compliance level based on the input data.
    Returns: {"complianceLevel": int}
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                return json.loads(input)
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")
        # Parse JSON if needed
        data = _parse_input(input)

        # Drill down past response/result wrappers if present
        data = data.get("response", data).get("result", data)

        #Return the compliance level
        return {"complianceLevel": data.get("complianceLevel", 0)}
    except Exception as e:
        return {"complianceLevel": 0, "error": str(e)}