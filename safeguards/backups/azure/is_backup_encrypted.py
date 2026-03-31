"""
Transformation: isBackupEncrypted
Vendor: Azure Recovery Services / Azure Data Protection
Category: Backup / Data Protection

Checks that all Azure backup vaults have encryption configured.
Azure vaults are always encrypted at rest with Platform Managed Keys (PMK)
at minimum; this check verifies encryption is present and reports whether
Customer Managed Keys (CMK) are in use for stronger protection.

Data source: Azure Resource Graph query returning vault encryption settings
including encryptionMode (PMK/CMK), state, and keyUri.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEncrypted", "vendor": "Azure", "category": "Backup"}
        }
    }


def transform(input):
    """Evaluates encryption status across all Azure backup vaults via Resource Graph data."""
    criteriaKey = "isBackupEncrypted"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Resource Graph table response or direct totalRecords check
        inner_data = data.get("data", data)
        rows = inner_data.get("rows", [])

        # If no Resource Graph rows, fall back to totalRecords check
        if not rows:
            total = data.get("totalRecords", inner_data.get("totalRecords", -1))
            if total >= 0:
                all_encrypted = total > 0
                if all_encrypted:
                    pass_reasons.append("Backup vaults found with encryption configured")
                else:
                    fail_reasons.append("No backup vaults found")
                    recommendations.append("Create Azure backup vaults with encryption enabled")
                return create_response(
                    result={criteriaKey: all_encrypted}, validation=validation,
                    pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations
                )

        # Parse Resource Graph rows for encryption details
        vaults_evaluated = 0
        cmk_vaults = []
        pmk_vaults = []

        for row in rows:
            if isinstance(row, list):
                # Expected: name, type, subscriptionId, resourceGroup, location,
                # encryptionMode, state, infrastructureEncryption, keyUri, kekIdentityType, kekIdentityId
                vault_name = row[0] if len(row) > 0 else "Unknown"
                encryption_mode = row[5] if len(row) > 5 else "Unknown"
            elif isinstance(row, dict):
                vault_name = row.get("name", "Unknown")
                encryption_mode = row.get("encryptionMode", "Unknown")
            else:
                continue

            vaults_evaluated += 1
            if encryption_mode == "CMK":
                cmk_vaults.append(vault_name)
            else:
                pmk_vaults.append(vault_name)

        # All Azure vaults are encrypted (PMK at minimum), so presence = encrypted
        all_encrypted = vaults_evaluated > 0

        if all_encrypted:
            pass_reasons.append(f"All {vaults_evaluated} backup vaults are encrypted at rest")
            if cmk_vaults:
                pass_reasons.append(f"{len(cmk_vaults)} vault(s) use Customer Managed Keys (CMK)")
            if pmk_vaults:
                pass_reasons.append(f"{len(pmk_vaults)} vault(s) use Platform Managed Keys (PMK)")
        else:
            fail_reasons.append("No backup vaults found in subscription")
            recommendations.append("Create Azure backup vaults to protect critical resources")

        return create_response(
            result={criteriaKey: all_encrypted, "vaultsEvaluated": vaults_evaluated, "cmkVaults": len(cmk_vaults), "pmkVaults": len(pmk_vaults)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"vaultsEvaluated": vaults_evaluated, "cmkCount": len(cmk_vaults), "pmkCount": len(pmk_vaults)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
