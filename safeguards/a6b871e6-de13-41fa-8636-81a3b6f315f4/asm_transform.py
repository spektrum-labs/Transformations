# asm_transform.py

import json

def transform(input):
    """
    Transforms all of the Attack Surface Management data into a single object.
    Returns: {"isASMEnabled": bool, "isASMLoggingEnabled": bool}
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
        default_value = True if input is not None else False

        if 'errors' in input:
            default_value = False
            
        is_asm_enabled = input.get('isASMEnabled', default_value)
        is_asm_logging_enabled = input.get('isASMLoggingEnabled', default_value)

        if 'SCHEDULED_SCAN_LIST_OUTPUT' in input:
            scheduled_scan_list_output = input.get('SCHEDULED_SCAN_LIST_OUTPUT', {}).get("RESPONSE", {}).get("SCHEDULED_SCAN_LIST", {}).get("SCAN", [])
            
            if scheduled_scan_list_output and len(scheduled_scan_list_output) > 0:
                is_asm_enabled = True
                is_asm_logging_enabled = True

        asm_info = {
            "isASMEnabled": is_asm_enabled,
            "isASMLoggingEnabled": is_asm_logging_enabled
        }
        return asm_info
    except Exception as e:
        return {"isASMEnabled": False, "isASMLoggingEnabled": False, "error": str(e)}