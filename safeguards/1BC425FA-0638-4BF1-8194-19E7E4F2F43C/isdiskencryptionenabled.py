"""
Transformation: isDiskEncryptionEnabled
Vendor: Sophos (Intercept X / Central)
Category: Endpoint Security / Encryption  (Marsh EPP-06: Encrypted Drives)

Derives disk-encryption coverage from the Sophos endpoints response by counting
devices that report encrypted volumes (endpoint.encryption.volumes), mirroring
the counting already performed in epp_transform.py.
"""
import json
from datetime import datetime


def transform(input):
    def extract_input(input_data):
        if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
            return input_data["data"], input_data["validation"]
        data = input_data
        if isinstance(data, dict):
            for _ in range(3):
                unwrapped = False
                for key in ["api_response", "response", "result", "apiResponse", "Output"]:
                    if key in data and isinstance(data.get(key), dict):
                        data = data[key]; unwrapped = True; break
                if not unwrapped:
                    break
        return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

    def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                        recommendations=None, input_summary=None, transformation_errors=None,
                        api_errors=None, additional_findings=None):
        if validation is None:
            validation = {"status": "unknown", "errors": [], "warnings": []}
        return {
            "transformedResponse": result,
            "additionalInfo": {
                "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
                "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
                "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
                "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDiskEncryptionEnabled", "vendor": "Sophos", "category": "Endpoint Security"}
            }
        }

    try:
        if isinstance(input, str): input = json.loads(input)
        elif isinstance(input, bytes): input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={"isDiskEncryptionEnabled": False}, validation=validation, fail_reasons=["Input validation failed"])

        # Token-Service may deliver endpoints as a bare list or under 'items'
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("items") or []
        else:
            items = []
        if not isinstance(items, list):
            items = []

        total = len(items)
        encrypted = 0
        for ep in items:
            if isinstance(ep, dict) and ep.get("encryption", {}).get("volumes"):
                encrypted += 1

        coverage = round((encrypted / total) * 100, 2) if total else 0
        # Convention: pass when the fleet is reporting AND at least one device is encrypted.
        # NOTE (design decision for Joshua): to require a stricter threshold for
        # "Encrypted Drives", change the line below to `coverage >= REQUIRED_COVERAGE`.
        is_enabled = total > 0 and encrypted > 0

        pass_reasons, fail_reasons, recommendations = [], [], []
        if is_enabled:
            pass_reasons.append(f"Disk encryption present on {encrypted}/{total} devices ({coverage}%)")
        elif total == 0:
            fail_reasons.append("No endpoints reporting - cannot confirm disk encryption")
            recommendations.append("Ensure endpoints are enrolled and reporting")
        else:
            fail_reasons.append(f"No encrypted volumes reported across {total} devices")
            recommendations.append("Enable full-disk encryption (e.g., BitLocker/FileVault) on all endpoints")

        return create_response(
            result={"isDiskEncryptionEnabled": is_enabled},
            validation=validation, pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            additional_findings=[{"metric": "encryptionCoveragePercent", "value": coverage}],
            input_summary={"encryptedDevices": encrypted, "totalDevices": total, "coveragePercent": coverage})
    except Exception as e:
        return create_response(result={"isDiskEncryptionEnabled": False}, validation={"status": "error", "errors": [], "warnings": []}, transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
