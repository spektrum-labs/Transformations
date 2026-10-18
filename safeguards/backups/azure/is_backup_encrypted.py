"""
Transformation: isBackupEncrypted
Vendor: Azure Recovery Services / Azure Data Protection
Category: Backup / Data Protection

Checks that all Azure backup vaults have encryption configured.
Azure vaults are always encrypted at rest with Platform Managed Keys (PMK)
at minimum; this check reports whether Customer Managed Keys (CMK) are in use
for stronger protection.

Data source: Azure Resource Graph query returning vault encryption settings
including encryptionMode (PMK/CMK), state, and keyUri.

A vault counts as encrypted only when its row states a recognised mode (CMK, PMK, or the Data
Protection state Enabled or Disabled). The existence of a vault is not evidence: a row with no
mode, an empty or Unknown mode, or any other value says nothing about that vault, so the criterion
is None (Not evaluated) together with a dataCollection error. A vault whose Data Protection state
is Inconsistent has customer-managed key settings that are not applied consistently, which is a
real False. Azure Backup has no unencrypted mode, so that is the only False these rows can show.
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
    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get("isBackupEncrypted") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["isBackupEncrypted could not be measured from the response"]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error",
                               "errors": [] if measured else not_measured_reasons},
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
            return create_response(result={criteriaKey: None}, validation=validation, fail_reasons=["Input validation failed"])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        inner_data = data.get("data", data) if isinstance(data, dict) else None
        rows = inner_data.get("rows") if isinstance(inner_data, dict) else None
        rows = rows if isinstance(rows, list) else []

        # Zero Resource Graph rows is not a measured answer. Resource Graph is RBAC-scoped:
        # a scope the caller cannot read at all answers 403, but a PARTIALLY readable scope
        # answers 200 with only the readable subset and, in Microsoft's words, "without any
        # indication that the result might be partial". So zero rows is equally "there are
        # none" and "the vaults are in a subscription this principal cannot read", and the
        # response carries nothing that tells them apart. See CONTRIBUTING.md, "Azure
        # Resource Graph: zero rows is not a proven empty set".
        # This also retires the totalRecords fallback that used to stand here. totalRecords
        # is Resource Graph's OWN count of matched records, so zero there is the same
        # ambiguous reading as zero rows; and its other branch asserted isBackupEncrypted
        # True from totalRecords > 0 alone, which is a count of vaults, not a reading of
        # any vault's encryption. Both are gone rather than left reachable.
        if not rows:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["isBackupEncrypted not evaluated: the Resource Graph query returned zero rows, "
                            "which is also what a subscription this principal cannot read returns"],
                recommendations=["Confirm the principal has at least Reader on every subscription "
                                 "holding a Recovery Services or Backup vault, then re-run the query."]
            )

        # Parse Resource Graph rows for encryption details. A vault counts only when its row states a
        # recognised mode; the presence of a row is not a reading of the vault's encryption.
        vaults_evaluated = 0
        cmk_vaults = []
        pmk_vaults = []
        inconsistent_vaults = []
        unverified_vaults = []
        recognised_pmk = ("pmk", "enabled", "disabled")

        for row in rows:
            if isinstance(row, list):
                # Expected: name, type, subscriptionId, resourceGroup, location,
                # encryptionMode, state, infrastructureEncryption, keyUri, kekIdentityType, kekIdentityId
                vault_name = row[0] if len(row) > 0 else "Unknown"
                encryption_mode = row[5] if len(row) > 5 else None
            elif isinstance(row, dict):
                vault_name = row.get("name", "Unknown")
                encryption_mode = row.get("encryptionMode")
            else:
                continue

            vaults_evaluated += 1
            mode = encryption_mode.strip().lower() if isinstance(encryption_mode, str) else ""
            if mode == "cmk":
                cmk_vaults.append(vault_name)
            elif mode in recognised_pmk:
                pmk_vaults.append(vault_name)
            elif mode == "inconsistent":
                inconsistent_vaults.append(vault_name)
            else:
                unverified_vaults.append(vault_name)

        counts = {"vaultsEvaluated": vaults_evaluated, "cmkVaults": len(cmk_vaults), "pmkVaults": len(pmk_vaults),
                  "inconsistentVaults": len(inconsistent_vaults), "unverifiedVaults": len(unverified_vaults)}

        if vaults_evaluated == 0:
            return create_response(
                result=dict({criteriaKey: None}, **counts),
                validation=validation,
                api_errors=["isBackupEncrypted not evaluated: the response held no readable vault row"]
            )

        if inconsistent_vaults:
            # Stated by Azure: the vault's customer-managed key settings are not applied consistently.
            all_encrypted = False
            fail_reasons.append(f"{len(inconsistent_vaults)} backup vault(s) report an inconsistent encryption state")
            recommendations.append("Repair the customer-managed key settings on the vaults reporting an inconsistent state")
        elif unverified_vaults:
            # A row with no recognised mode proves nothing about that vault: not evaluated, never a pass.
            return create_response(
                result=dict({criteriaKey: None}, **counts),
                validation=validation,
                api_errors=[f"isBackupEncrypted not evaluated: {len(unverified_vaults)} of {vaults_evaluated} vault row(s) "
                            "state no recognised encryption mode, so their encryption could not be read"],
                recommendations=["Re-run the Resource Graph vault encryption query and confirm each vault row carries an encryptionMode"]
            )
        else:
            all_encrypted = True
            pass_reasons.append(f"All {vaults_evaluated} backup vaults state an encryption mode (encrypted at rest)")
            if cmk_vaults:
                pass_reasons.append(f"{len(cmk_vaults)} vault(s) use Customer Managed Keys (CMK)")
            if pmk_vaults:
                pass_reasons.append(f"{len(pmk_vaults)} vault(s) use Platform Managed Keys (PMK)")

        return create_response(
            result=dict({criteriaKey: all_encrypted}, **counts),
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=dict(counts)
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
