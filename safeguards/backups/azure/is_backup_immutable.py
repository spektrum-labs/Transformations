"""
Transformation: isBackupImmutable
Vendor: Azure Recovery Services / Azure Data Protection
Category: Backup / Data Protection

Checks that backup vaults have soft delete enabled with a retention period,
confirming immutability protection is active.

Data source: Azure Resource Graph query returning vault soft delete settings
including softDeleteState and softDeleteRetentionPeriodInDays.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupImmutable", "vendor": "Azure", "category": "Backup"}
        }
    }


def transform(input):
    """Evaluates soft delete / immutability across all Azure backup vaults via Resource Graph data."""
    criteriaKey = "isBackupImmutable"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Check for single-vault immutabilitySettings format (properties.immutabilitySettings.state)
        if isinstance(data, dict) and "properties" in data:
            immutability = data.get("properties", {}).get("immutabilitySettings", {})
            if isinstance(immutability, dict):
                imm_state = immutability.get("state", "NotConfigured")
                is_immutable = imm_state in ("Locked", "Unlocked")

                if is_immutable:
                    pass_reasons.append(f"Vault immutability state is {imm_state}")
                else:
                    fail_reasons.append(f"Vault immutability state is {imm_state or 'NotConfigured'}")
                    recommendations.append("Enable immutable vault (WORM) on the Azure Recovery Services vault")

                return create_response(
                    result={criteriaKey: is_immutable, "immutabilityState": imm_state},
                    validation=validation,
                    pass_reasons=pass_reasons,
                    fail_reasons=fail_reasons,
                    recommendations=recommendations,
                    input_summary={"immutabilityState": imm_state}
                )

        # Handle list input (e.g. merge=false sending vault array directly)
        # or dict with nested data/rows from Resource Graph
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            inner_data = data.get("data", data)
            if isinstance(inner_data, dict):
                rows = inner_data.get("rows", [])
            elif isinstance(inner_data, list):
                rows = inner_data
            else:
                rows = []
        else:
            rows = []

        if not rows:
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["No backup vaults found in subscription"],
                recommendations=["Create Azure Recovery Services or Backup vaults and enable soft delete"]
            )

        all_immutable = True
        vaults_evaluated = 0
        non_immutable_vaults = []

        for row in rows:
            # Resource Graph rows may be lists (positional) or dicts
            if isinstance(row, list):
                # Expected columns: name, type, subscriptionId, resourceGroup, location,
                # softDeleteState, softDeleteRetentionPeriodInDays, isSoftDeleteEnabled,
                # hasRetentionPeriod, isImmutable, properties
                vault_name = row[0] if len(row) > 0 else "Unknown"
                raw_immutable = row[9] if len(row) > 9 else False
            elif isinstance(row, dict):
                vault_name = row.get("name", "Unknown")
                raw_immutable = row.get("isImmutable", False)
            else:
                continue

            # Handle string values like "0"/"1" from Resource Graph
            if isinstance(raw_immutable, str):
                is_immutable = raw_immutable.lower() in ("1", "true", "yes")
            else:
                is_immutable = bool(raw_immutable)

            vaults_evaluated += 1
            if not is_immutable:
                all_immutable = False
                non_immutable_vaults.append(vault_name)

        if all_immutable and vaults_evaluated > 0:
            pass_reasons.append(f"All {vaults_evaluated} backup vaults have soft delete enabled with retention (immutable)")
        else:
            fail_reasons.append(f"{len(non_immutable_vaults)} vault(s) lack immutability protection: {', '.join(non_immutable_vaults[:5])}")
            recommendations.append("Enable soft delete with a retention period on all Azure backup vaults to ensure immutability")

        return create_response(
            result={criteriaKey: all_immutable and vaults_evaluated > 0, "vaultsEvaluated": vaults_evaluated, "nonImmutableVaults": non_immutable_vaults},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"vaultsEvaluated": vaults_evaluated, "nonImmutableCount": len(non_immutable_vaults)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
