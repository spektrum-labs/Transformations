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
    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get("isBackupImmutable") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["isBackupImmutable could not be measured from the response"]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error",
                               "errors": [] if measured else not_measured_reasons},
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

        # Zero Resource Graph rows is not a measured answer. Resource Graph is RBAC-scoped:
        # a scope the caller cannot read at all answers 403, but a PARTIALLY readable scope
        # answers 200 with only the readable subset and, in Microsoft's words, "without any
        # indication that the result might be partial". So zero rows is equally "there are
        # none" and "the vaults are in a subscription this principal cannot read", and the
        # response carries nothing that tells them apart. See CONTRIBUTING.md, "Azure
        # Resource Graph: zero rows is not a proven empty set".
        if not rows:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["isBackupImmutable not evaluated: the Resource Graph query returned zero rows, which is also what a subscription this principal cannot read returns"],
                recommendations=["Confirm the principal has at least Reader on every subscription "
                                 "holding a Recovery Services or Backup vault, then re-run the query."]
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

            vaults_evaluated = vaults_evaluated + 1
            if not is_immutable:
                all_immutable = False
                non_immutable_vaults.append(vault_name)

        if all_immutable and vaults_evaluated > 0:
            pass_reasons.append(f"All {vaults_evaluated} backup vaults have soft delete enabled with retention (immutable)")
        else:
            display_vaults = non_immutable_vaults if len(non_immutable_vaults) <= 5 else list(non_immutable_vaults[i] for i in range(5))
            fail_reasons.append(f"{len(non_immutable_vaults)} vault(s) lack immutability protection: {', '.join(display_vaults)}")
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
