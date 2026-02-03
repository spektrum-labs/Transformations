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
    Confirms SIEM data export (S3 or Splunk) is configured for logging

    Parameters:
        input (dict): Organization data from GET /organizations/{id}

    Returns:
        dict: {"isDataExportConfigured": boolean}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Check for data export configuration
        data_export_enabled = data.get("data_export_enabled", False)

        # Also check for specific export configurations
        s3_export = data.get("s3_export", {})
        splunk_export = data.get("splunk_export", {})

        s3_configured = s3_export.get("enabled", False) if s3_export else False
        splunk_configured = splunk_export.get("enabled", False) if splunk_export else False

        is_configured = data_export_enabled or s3_configured or splunk_configured

        return {
            "isDataExportConfigured": is_configured,
            "s3Export": s3_configured,
            "splunkExport": splunk_configured
        }

    except Exception as e:
        return {"isDataExportConfigured": False, "error": str(e)}
