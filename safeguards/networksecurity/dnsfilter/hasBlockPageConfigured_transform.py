import json
import ast


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


def transform(input):
    """
    Verifies custom block pages are configured for user notification

    Parameters:
        input (dict): Block pages data from GET /block_pages

    Returns:
        dict: {"hasBlockPageConfigured": boolean, "blockPageCount": int}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        block_pages = data if isinstance(data, list) else data.get("blockPages", data.get("block_pages", []))

        # Count enabled block pages
        enabled_pages = []
        for page in block_pages:
            if page.get("enabled", True):  # Default to True if not specified
                enabled_pages.append(page)

        has_configured = len(enabled_pages) > 0

        return {
            "hasBlockPageConfigured": has_configured,
            "blockPageCount": len(enabled_pages),
            "totalBlockPages": len(block_pages)
        }

    except Exception as e:
        return {"hasBlockPageConfigured": False, "error": str(e)}
