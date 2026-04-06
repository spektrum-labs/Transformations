import json
import ast


def transform(input):
    """
    Evaluates isSecurityScanningEnabled for GitLab

    Checks: Whether SAST/DAST vulnerability scanning is configured and returning findings
    API Source: {baseURL}/api/v4/projects/{projectId}/vulnerability_findings
    Pass Condition: Vulnerability findings endpoint returns data indicating scanners are active

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecurityScanningEnabled": boolean, "findingsCount": int, "scanners": list}
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
        findings = data if isinstance(data, list) else data.get("data", data.get("items", data.get("results", [])))

        if not isinstance(findings, list):
            return {
                "isSecurityScanningEnabled": False,
                "findingsCount": 0,
                "scanners": [],
                "error": "Unexpected response format"
            }

        scanners = list(set(
            f.get("scanner", {}).get("name", "unknown")
            for f in findings
            if isinstance(f, dict) and f.get("scanner")
        ))

        result = len(findings) > 0 or len(scanners) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isSecurityScanningEnabled": result,
            "findingsCount": len(findings),
            "scanners": scanners
        }

    except Exception as e:
        return {"isSecurityScanningEnabled": False, "error": str(e)}
