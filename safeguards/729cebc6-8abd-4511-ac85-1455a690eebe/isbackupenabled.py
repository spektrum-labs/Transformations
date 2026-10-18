"""
Transformation: isBackupEnabled
Vendor: Azure Recovery Services
Category: Backup / Data Protection

Evaluates whether Azure Backup is enabled: True when at least one protected item (a VM, file
share or database) in a vault is actively protected, False when the vaults' protected items were read
whole and none is active.

Data source: the per-vault protected items list (Azure Backup protectedItems read), as
{"protectedItems": [page, ...]} or a single {"value": [...]} page.

The Resource Graph vault table (getBackupDiagnosticSettings: vaults and their diagnostic settings) is
not evidence of backup. It proves a vault exists, so it used to turn every account with a vault into
a pass. A body that does not report protected items is None (Not evaluated) with a dataCollection
error; so is an empty vault list, a list with a nextLink or an unreadable page that holds no active item.
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
    value = result.get("isBackupEnabled") if isinstance(result, dict) else None
    measured = value is not None
    not_measured_reasons = api_errors or transformation_errors or fail_reasons or ["isBackupEnabled could not be measured from the response"]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else not_measured_reasons
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isBackupEnabled",
                "vendor": "Azure",
                "category": "Backup"
            }
        }
    }


# Azure reports two separate fields. protectionState is the lifecycle ('Protected', 'ProtectionConfigured',
# 'IRPending', 'ProtectionStopped', 'ProtectionPaused', 'ProtectionError'). protectionStatus is health
# ('Healthy' or not). A stopped item keeps a 'Healthy' status while nothing is being backed up, so the
# lifecycle decides when it is present, and health is only the fallback for an item that has no state.
ACTIVE_STATES = ("protected", "protectionconfigured")
HEALTHY_STATUSES = ("healthy",)


def not_evaluated(validation, api_error, recommendation, transformation_errors=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={"isBackupEnabled": None},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[api_error],
        recommendations=[recommendation]
    )


def read_pages(data):
    """The per-vault pages of a protected items read, or None when the body is not that read.

    Accepts {"protectedItems": [page, ...]} or a single {"value": [...]} page, each page being the
    Azure Backup protectedItems list response."""
    if not isinstance(data, dict):
        return None
    if "protectedItems" in data:
        entries = data["protectedItems"]
    elif "value" in data:
        entries = [data]
    else:
        return None
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return None
    return entries


def transform(input):
    criteriaKey = "isBackupEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(
                validation,
                "isBackupEnabled not evaluated: input validation failed",
                "Re-evaluate this check once the Azure Backup read succeeds")

        # Backup is enabled when something is actively protected. A Resource Graph vault table (the
        # getBackupDiagnosticSettings read) lists vaults and their diagnostic settings: it proves vaults
        # exist, and that logs are routed, not that any item is backed up. So only a protected items
        # read can answer; any other body, including vault rows, is Not evaluated, never a pass.
        pages = read_pages(data)
        if pages is None:
            return not_evaluated(
                validation,
                "isBackupEnabled not evaluated: the response does not report protected items. A vault list or "
                "diagnostic settings row shows a vault exists, not that anything is backed up",
                "Read the vaults' protected items (Azure Backup protectedItems) to evaluate this check")
        if len(pages) == 0:
            # The vault listing is empty both when no vault exists and when the subscription cannot be read.
            return not_evaluated(
                validation,
                "isBackupEnabled not evaluated: no vault was read, which is also what a subscription this "
                "principal cannot read returns",
                "Verify the Azure Backup connection can read the subscriptions that hold the vaults, then re-evaluate this check")

        unreadable = 0
        total_items = 0
        active_items = []
        for page in pages:
            if isinstance(page, list):
                page = {"value": page}
            if not isinstance(page, dict) or "error" in page or not isinstance(page.get("value"), list):
                unreadable += 1
                continue
            if page.get("nextLink"):
                # More items exist than were read, so an absence of active items proves nothing.
                unreadable += 1
            for item in page["value"]:
                if not isinstance(item, dict) or not isinstance(item.get("properties"), dict):
                    unreadable += 1
                    continue
                total_items += 1
                props = item["properties"]
                state = str(props.get("protectionState") or "").lower()
                health = str(props.get("protectionStatus") or "").lower()
                active = state in ACTIVE_STATES if state else health in HEALTHY_STATUSES
                if active:
                    active_items.append(item.get("name", "Unknown"))

        if len(active_items) == 0 and unreadable > 0:
            return not_evaluated(
                validation,
                "isBackupEnabled not evaluated: not every vault's protected items could be read, so the absence "
                "of protected items is not proven",
                "Verify the Azure Backup connection can read protected items in every vault, then re-evaluate this check")

        is_enabled = len(active_items) > 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_enabled:
            pass_reasons.append(f"Backup is enabled: {len(active_items)} actively protected item(s) found")
        else:
            fail_reasons.append("No actively protected backup items found")
            recommendations.append("Enable Azure Backup protection for the VMs, databases and storage accounts that need it")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"activeProtectedItems": len(active_items), "totalItems": total_items,
                           "vaultPagesRead": len(pages), "unreadable": unreadable}
        )

    except Exception as e:
        message = str(e)[:200]  # the text reaches the stored result, so a long one is cut
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            f"isBackupEnabled not evaluated: transformation error: {message}",
            "Re-evaluate this check once the Azure Backup read succeeds",
            transformation_errors=[message])
